/*
 * Zack-AI-Scanner —— Burp Suite 的 AI 智能漏洞扫描插件
 * Copyright (C) 2026 Zack AI Scanner
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package com.zackai.core;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import com.zackai.i18n.Msg;
import com.zackai.model.ScanTask;
import com.zackai.ui.LogPanel;
import com.zackai.ui.MainPanel;
import java.util.List;
import javax.swing.SwingUtilities;

/**
 * Proxy 流量的自动扫描：配置页勾上「Proxy 流量自动扫描」后，每条经过代理的**请求**都会新建一条
 * AI 智能扫描任务（{@link ScanTask.ScanMode#CUSTOM}），可用白名单（{@link ProxyScanFilter}）
 * 把范围收到指定 host；白名单留空就是全部。
 *
 * <p>几件必须保持的事：
 * <ul>
 *   <li><b>只看请求方向</b>：{@code processProxyMessage} 请求/响应各来一次，响应那次直接返回；</li>
 *   <li><b>快照，不留引用</b>：{@code message.getMessageInfo()} 返回的对象 Burp 还会继续改
 *       （别的监听器或用户改包都会体现在同一个对象上），而我们的任务要过一会儿才跑。
 *       这里当场把请求字节与服务拷成不可变对象再交给任务；</li>
 *   <li><b>回 EDT</b>：{@link MainPanel#addRequest} 里是 {@code tasks.add} + {@code taskIdCounter++}
 *       （没有同步），而 EDT 上每秒有一次 {@code updateStats()} 在遍历 tasks —— 代理线程直接调它会
 *       撞出 ConcurrentModificationException，正是这个仓库反复踩过的那类静默失败；</li>
 *   <li><b>不会自己扫自己</b>：扫描发出的测试请求走 {@code callbacks.makeHttpRequest}，
 *       不经过代理，所以不会再触发本监听器（否则就是无限放大）。</li>
 *   <li><b>只收带参数的请求</b>：判定复用 {@link AIEngine#injectableProxyParamNames}（与 step2 同一份
 *       参数谓词，且与去重键同源）。图片/CSS/JS/favicon 这类没有参数的流量一条任务都不建 —— 它们本来
 *       也只会跑成「AI 未发现值得测试的参数 → 安全」，白搭一次重放和一次 AI 调用。跳过同样是静默的。</li>
 * </ul>
 */
public class ProxyAutoScanListener implements IProxyListener {

    private final MainPanel mainPanel;
    private final LogPanel logPanel;
    private final IExtensionHelpers helpers;

    public ProxyAutoScanListener(MainPanel mainPanel, LogPanel logPanel, IExtensionHelpers helpers) {
        this.mainPanel = mainPanel;
        this.logPanel = logPanel;
        this.helpers = helpers;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (!messageIsRequest || message == null || this.mainPanel == null) {
            return;
        }
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        if (!config.isAutoScanProxy()) {
            return;
        }
        IHttpRequestResponse info = message.getMessageInfo();
        if (info == null || info.getRequest() == null || info.getHttpService() == null) {
            return;
        }
        IHttpService service = info.getHttpService();
        if (!ProxyScanFilter.isWhitelisted(config.getAutoScanWhitelist(), service.getHost(), service.getPort())) {
            return;
        }
        byte[] requestBytes = info.getRequest();
        if (requestBytes.length == 0) {
            return;                                           // 空请求没什么可扫的（addRequest 也只会记一条错误）
        }
        // 参数名一次解析、两处用：既是闸门（没参数就不建任务 —— 图片/CSS/JS/纯 REST 路径），
        // 也是去重键的组成部分。两边共用同一份定义，见 AIEngine.injectableProxyParamNames。
        // 这一闸放在去重之前：参数都没解析出来的请求不该去占去重记录的位置（那张表有上限）。
        // null = 解析失败 → 放行（静默闸门宁可多建一条，也不要无声漏掉流量）。
        List<String> paramNames = AIEngine.injectableProxyParamNames(this.helpers, requestBytes);
        if (paramNames != null && paramNames.isEmpty()) {
            return;
        }
        String host = service.getHost();
        int port = service.getPort();
        // 去重：同一个功能点（方法 + 路径 + 参数**名**）只扫一次，参数值与请求头都不参与 ——
        // 没有这一步，刷新页面、轮询接口（带时间戳/分页/随机 nonce）、重复加载的静态资源都会各自
        // 变成一条任务，几十倍的发包与 AI 花费。
        // 跳过是**静默**的：重复本来就是常态，每次都记一行就等于把日志刷没了。
        if (!ProxyScanHistory.firstTime(ProxyScanHistory.key(host, port, requestBytes, paramNames))) {
            return;
        }
        final Snapshot snapshot = new Snapshot(requestBytes.clone(), host, port, service.getProtocol());
        if (this.logPanel != null) {
            // 无人值守的功能必须留下痕迹：任务列表里多出来的行要能对上「它为什么在这儿」
            this.logPanel.logInfo(Msg.t("log.autoscan.hit", host + ":" + port));
        }
        SwingUtilities.invokeLater(() -> this.mainPanel.addRequest(snapshot, ScanTask.ScanMode.CUSTOM));
    }

    /**
     * 请求的不可变快照：任务要一直持有它（报告、详情面板、基线都从这上面取）。
     * 不实现 setter（这个仓库里没有任何地方对存下来的请求调 set*），这样谁也别想事后改它。
     */
    static final class Snapshot implements IHttpRequestResponse {
        private final byte[] request;
        private final IHttpService service;

        Snapshot(byte[] request, String host, int port, String protocol) {
            this.request = request;
            this.service = new FixedHttpService(host, port, protocol);
        }

        @Override
        public byte[] getRequest() {
            return this.request;
        }

        @Override
        public void setRequest(byte[] message) {
            throw new UnsupportedOperationException(Msg.t("err.snapshotImmutable"));
        }

        @Override
        public byte[] getResponse() {
            return null;
        }

        @Override
        public void setResponse(byte[] message) {
            throw new UnsupportedOperationException(Msg.t("err.snapshotImmutable"));
        }

        @Override
        public String getComment() {
            return null;
        }

        @Override
        public void setComment(String comment) {
            throw new UnsupportedOperationException(Msg.t("err.snapshotImmutable"));
        }

        @Override
        public String getHighlight() {
            return null;
        }

        @Override
        public void setHighlight(String color) {
            throw new UnsupportedOperationException(Msg.t("err.snapshotImmutable"));
        }

        @Override
        public IHttpService getHttpService() {
            return this.service;
        }

        @Override
        public void setHttpService(IHttpService httpService) {
            throw new UnsupportedOperationException(Msg.t("err.snapshotImmutable"));
        }
    }

    /** 与 {@link Snapshot} 配套的服务信息（Burp 的 {@link IHttpService} 本来就只有 getter） */
    static final class FixedHttpService implements IHttpService {
        private final String host;
        private final int port;
        private final String protocol;

        FixedHttpService(String host, int port, String protocol) {
            this.host = host;
            this.port = port;
            this.protocol = protocol == null || protocol.isEmpty() ? "http" : protocol;
        }

        @Override
        public String getHost() {
            return this.host;
        }

        @Override
        public int getPort() {
            return this.port;
        }

        @Override
        public String getProtocol() {
            return this.protocol;
        }
    }
}
