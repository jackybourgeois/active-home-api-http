package org.activehome.api.http;

/*
 * #%L
 * Active Home :: API :: Http
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2016 Active Home Project
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the 
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public 
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/gpl-3.0.html>.
 * #L%
 */


import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import io.undertow.Undertow;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.*;
import io.undertow.server.handlers.resource.ClassPathResourceManager;
import io.undertow.server.handlers.resource.FileResourceManager;
import io.undertow.server.handlers.resource.ResourceHandler;
import io.undertow.server.session.*;
import io.undertow.util.Headers;
import io.undertow.util.StatusCodes;
import org.activehome.api.API;
import org.activehome.com.Notif;
import org.activehome.com.Request;
import org.activehome.com.RequestCallback;
import org.activehome.com.Response;
import org.activehome.com.helper.JsonHelper;
import org.activehome.com.error.Error;
import org.activehome.com.error.ErrorType;
import org.activehome.tools.Util;
import org.activehome.tools.file.FileHelper;
import org.activehome.context.data.UserInfo;
import org.kevoree.annotation.*;
import org.kevoree.log.Log;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

import static io.undertow.Handlers.resource;

/**
 * @author Jacky Bourgeois
 * @version %I%, %G%
 */
@ComponentType
public class HttpAPI extends API {

    @Param(defaultValue = "Allow the system to receive and send Message throw http (web server).")
    private String description;
    @Param(defaultValue = "/active-home-api-http")
    private String src;

    @Param(defaultValue = "localhost")
    private String address;
    @Param(defaultValue = "443")
    private int port;
    @Param(defaultValue = "true")
    private boolean isHttps;

    private Undertow server;
    private PathHandler pathHandler;

    private HashMap<UUID, HttpServerExchange> reqWaitingForSysRespMap;
    private HashMap<String, LinkedList<String>> loggedInHandlerMap;

    @Start
    public void start() {
        super.start();
        loggedInHandlerMap = new HashMap<>();
        reqWaitingForSysRespMap = new HashMap<>();
        pathHandler = new PathHandler();

        pathHandler.addPrefixPath("/bower_components", resource(new FileResourceManager(
                new File(System.getProperty("active-home.home") + "/bower_components"), 100)));
        pathHandler.addPrefixPath("/notif", exchange -> exchange.dispatch(() -> {
            String body = HttpHelper.readBody(exchange);

            Notif notif = new Notif(JsonObject.readFrom(body));
            sendNotif(notif);

            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/javascript");
            exchange.getResponseSender().send(JsonValue.TRUE.toString());
            exchange.endExchange();
        }));
        pathHandler.addPrefixPath("/", new ResourceHandler(
                new ClassPathResourceManager(this.getClass().getClassLoader())) {
            @Override
            public void handleRequest(HttpServerExchange exchange) throws Exception {
                super.handleRequest(exchange);
            }
        });

        if (isHttps) {
            startServerHttps();
        } else {
            startServerHttp();
        }
    }

    public void startServerHttps() {
        Log.info("Starting https server on: " + address + ":" + port);
        SessionAttachmentHandler sah = configureSession();
        server = Undertow.builder().addHttpsListener(port, address, createSSLContext())
                .setHandler(sah).build();
        server.start();

    }

    public SSLContext createSSLContext() {
        try {
            String ksName = System.getProperty("active-home.home") + "/keystore.jks";
            Properties prop = Util.loadProperties(
                    System.getProperty("active-home.home") + "/properties/config.properties");
            char ksPass[] = prop.getProperty("ssh_ks").toCharArray();
            char ctPass[] = prop.getProperty("ssh_ct").toCharArray();

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(ksName), ksPass);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, ctPass);
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(kmf.getKeyManagers(), null, null);
            return sc;
        } catch (NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException |
                KeyManagementException | KeyStoreException | IOException e) {
            e.printStackTrace();
            Log.error(e.getMessage());
        }
        return null;
    }

    public void startServerHttp() {
        SessionAttachmentHandler sah = configureSession();
        Log.info("Starting http server on: " + address + ":" + port);
        server = Undertow.builder().addHttpListener(port, address)
                .setHandler(sah).build();
        server.start();
    }

    @Stop
    public void stop() {
        if (server != null) server.stop();
    }

    @Override
    public void sendOutside(String msgStr) {
        JsonObject jsonMsg = JsonObject.readFrom(msgStr);
        if (jsonMsg.get("dest") != null
                && jsonMsg.get("dest").asString().startsWith(getFullId() + "://")) {
            UUID id = UUID.fromString(jsonMsg.get("id").asString());
            if (jsonMsg.get("method") != null) {

            } else if (jsonMsg.get("result") != null) {
                sendResponseOutside(id, jsonMsg);
            }
        }
    }

    public void sendResponseOutside(UUID id, JsonObject jsonMsg) {
        logInfo("send outside from: " + jsonMsg.get("src"));
        HttpServerExchange exchange = removeReqWaitingForSysResp(id);
        if (exchange != null) {
            Response response = new Response(jsonMsg);
            if (response.getResult() instanceof JsonObject) {
                JsonObject result = (JsonObject) response.getResult();
                if (result.get("content") != null) {                           // serve content
                    exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, result.get("mime").asString());
                    String content = result.get("content").asString();
                    if (content.startsWith("data:") && content.contains("base64,")) {
                        byte[] imgByteArray = Base64.getDecoder().decode(content.split("base64,")[1]);
                        exchange.getResponseSender().send(ByteBuffer.wrap(imgByteArray));
                    } else {
                        exchange.getResponseSender().send(content);
                    }
                } else if (result.get("wrap") != null) {                       // info for a component to load
                    exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/html");
                    exchange.getResponseSender().send(page(result.get("wrap").asObject()));
                } else {                                                       // otherwise, simply forward the result
                    exchange.getResponseSender().send(response.getResult().toString());
                }
            } else {                                                           // otherwise, simply forward the result
                exchange.getResponseSender().send(JsonHelper.objectToJson(response.getResult()).toString());
            }
            exchange.endExchange();
        }
    }

    public void addHandler(String path, final String dest, final boolean auth) {
        if (!loggedInHandlerMap.containsKey(path)) {
            System.out.println("handler not existing, add: " + path);
            loggedInHandlerMap.put(path, new LinkedList<>());
            pathHandler.removePrefixPath(path);
            pathHandler.addPrefixPath(path, exchange -> exchange.dispatch(() -> {
                // translate http request in Active Home request
                Request req = buildRequest(dest, exchange);
                // If no need for auth, push to system
                if (exchange.getRequestPath().startsWith("/auth/authenticate")) {
                    Request authReq = new Request(getFullId(), req.getDest(),
                            req.getTS(), req.getMethod(), req.getParams());
                    authReq.getEnviElem().put("api", "http");
                    sendRequest(authReq, new RequestCallback() {
                        public void success(Object result) {
                            auth((UUID) result, exchange);
                        }

                        public void error(Error result) {
                            permissionDenied(exchange);
                        }
                    });
                } else if (exchange.getRequestPath().startsWith("/auth/logout")) {
                    clearSession(exchange);
                    redirect(exchange, exchange.getRequestPath().replace("/auth/logout", ""));
                } else if (!auth) {
                    Request request = new Request(req.getSrc(), req.getDest(),
                            req.getTS(), req.getMethod(), req.getParams());
                    addReqWaitingForSysResp(request.getId(), exchange);
                    sendRequest(request, null);
                } else {
                    Session session = getSession(exchange);
                    if (session.getAttribute("token") != null) {
                        Request authReq = new Request(getFullId(), getNode() + ".auth", getCurrentTime(),
                                "checkToken", new Object[]{session.getAttribute("token")});
                        authReq.getEnviElem().put("api", "http");

                        sendRequest(authReq, new RequestCallback() {
                            public void success(Object result) {
                                // if user connected, push to user
                                if (!forwardToUser(path, req, exchange, (UserInfo) result)) {
                                    sendError(exchange, new Error(ErrorType.NOT_FOUND,
                                            "Unable to transmit to the user."));
                                }
                            }

                            public void error(Error result) {
                            }
                        });
                    } else if (exchange.getRequestPath().compareTo(path) == 0) {
                        // if request for view, redirect to auth form
                        redirect(exchange, "/auth/red" + exchange.getRequestPath());
                    } else {
                        // otherwise, refuse access
                        permissionDenied(exchange);
                    }
                }
            }));
        }

        if (auth) {
            boolean exists = false;
            for (String existingDest : loggedInHandlerMap.get(path)) {
                if (existingDest.compareTo(dest) == 0) exists = true;
                break;
            }
            if (!exists) loggedInHandlerMap.get(path).add(dest);
        }

    }

    public boolean forwardToUser(String path, Request req, HttpServerExchange exchange, UserInfo userInfo) {
        String src = userInfo.getHousehold() + "." + userInfo.getId() + "@" + exchange.getSourceAddress();
        String currentDest = userInfo.getHousehold() + req.getDest().substring(req.getDest().lastIndexOf("."));
        if (loggedInHandlerMap.containsKey(path)) {
            boolean exists = false;
            for (String dest : loggedInHandlerMap.get(path)) {
                if (dest.compareTo(currentDest) == 0) exists = true;
            }
            if (exists) {
                Request userReq = new Request(getFullId() + "://" + src, currentDest,
                        req.getTS(), req.getMethod(), req.getParams());
                userReq.getEnviElem().put("userInfo", userInfo);
                addReqWaitingForSysResp(userReq.getId(), exchange);
                sendToUser(userReq, null);
                return true;
            }
        }
        return false;
    }

    public void redirect(HttpServerExchange exchange, String location) {
        exchange.setResponseCode(StatusCodes.TEMPORARY_REDIRECT);
        exchange.getResponseHeaders().put(Headers.LOCATION, location);
        exchange.getResponseSender().close();
    }

    public void sendError(HttpServerExchange exchange, Error error) {
        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/javascript");
        exchange.getResponseSender().send(error.toString());
        exchange.endExchange();
    }

    public void permissionDenied(HttpServerExchange exchange) {
        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/javascript");
        exchange.getResponseSender().send(new Error(ErrorType.PERMISSION_DENIED, "Permission denied.").toString());
        exchange.endExchange();
    }

    String page(JsonObject wrap) {
        String page = FileHelper.fileToString("page.html", getClass().getClassLoader());
        return page.replaceAll("\\$\\{name\\}", wrap.get("name").asString())
                .replaceAll("\\$\\{description\\}", wrap.get("description").asString())
                .replaceAll("\\$\\{title\\}", wrap.get("title").asString())
                .replaceAll("\\$\\{url\\}", wrap.get("url").asString())
                .replaceAll("\\$\\{wsUrl\\}", "ws://" + address + ":" + 8092 + "/data");
    }

    Request buildRequest(String dest, HttpServerExchange exchange) {
        String src = exchange.getSourceAddress().getAddress() + ":" + exchange.getSourceAddress().getPort();
        String relPath = exchange.getRelativePath();

        Request req;
        if (relPath.endsWith(".js") || relPath.endsWith(".css") || relPath.endsWith(".html") || relPath.endsWith(".png")
                || relPath.endsWith(".jpg") || relPath.endsWith(".svg") || relPath.endsWith(".ico")) {
            req = new Request(getFullId() + "://" + src, dest, getCurrentTime(),
                    "file", new String[]{relPath.substring(1, relPath.length())});  // extension => file method (serve files)
        } else {
            Object[] params = relPath.split("/");
            Object[] checkedParams = new Object[params.length];
            for (int i = 0; i < params.length; i++) {
                try {
                    checkedParams[i] = Double.valueOf((String) params[i]);
                } catch (NumberFormatException e) {
                    checkedParams[i] = params[i];
                }
            }
            String body = HttpHelper.readBody(exchange);

            HashMap<String, Object> bodyMap = new HashMap<>();
            if (body.compareTo("") != 0) {
                JsonValue json = JsonValue.readFrom(body);
                JsonValue jsonParams = json.asObject().get("params");
                if (jsonParams != null) {
                    checkedParams = push(checkedParams, JsonHelper.jsonToObject(jsonParams));
                }

                JsonValue jsonEnviElem = json.asObject().get("enviElem");
                if (jsonEnviElem != null) {
                    for (String name : jsonEnviElem.asObject().names()) {
                        bodyMap.put(name, JsonHelper.jsonToObject(json.asObject().get(name)));
                    }
                }
            }


            if (checkedParams.length > 2) {                                                // Method + params
                req = new Request(getFullId() + "://" + src, dest, getCurrentTime(),
                        (String) checkedParams[1], Arrays.copyOfRange(checkedParams, 2, checkedParams.length));
            } else if (checkedParams.length == 2) {                                        // Method only
                req = new Request(getFullId() + "://" + src, dest, getCurrentTime(), (String) checkedParams[1]);
            } else {                                                                // Nothing => html method (view)
                req = new Request(getFullId() + "://" + src, dest, getCurrentTime(), "html");
            }

            req.getEnviElem().putAll(bodyMap);
        }
        return req;
    }

    public void removeHandler(String path) {
        pathHandler.removeExactPath(path);
    }

    HttpServerExchange removeReqWaitingForSysResp(UUID id) {
        return reqWaitingForSysRespMap.remove(id);
    }

    void addReqWaitingForSysResp(UUID uuid, HttpServerExchange exchange) {
        reqWaitingForSysRespMap.put(uuid, exchange);
    }

    public void auth(UUID token, HttpServerExchange exchange) {
        Session session = getSession(exchange);
        session.setAttribute("token", token);
        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/javascript");
        JsonObject result = new JsonObject();
        result.add("token", token.toString());
        exchange.getResponseSender().send(result.toString());
        exchange.endExchange();
    }

    UserInfo checkAuth(HttpServerExchange exchange) {
        Session session = getSession(exchange);
        if (session.getAttribute("user") != null) {
            return (UserInfo) session.getAttribute("user");
        }
        return null;
    }

    /**
     * Set up the session management
     *
     * @return
     */
    SessionAttachmentHandler configureSession() {
        SessionManager sessionManager = new InMemorySessionManager("SESSION_MANAGER");
        SessionCookieConfig sessionConfig = new SessionCookieConfig();
        SessionAttachmentHandler sessionAttachmentHandler =
                new SessionAttachmentHandler(sessionManager, sessionConfig);
        sessionAttachmentHandler.setNext(pathHandler);
        return sessionAttachmentHandler;
    }

    private static Session getSession(HttpServerExchange exchange) {
        SessionManager sm = exchange.getAttachment(SessionManager.ATTACHMENT_KEY);
        SessionConfig sessionConfig = exchange.getAttachment(SessionConfig.ATTACHMENT_KEY);
        //Map<String, Deque<String>> reqParams = exchange.getQueryParameters();
        Session session = sm.getSession(exchange, sessionConfig);
        if (session == null) session = sm.createSession(exchange, sessionConfig);
        return session;
    }

    void clearSession(HttpServerExchange exchange) {
        SessionManager sm = exchange.getAttachment(SessionManager.ATTACHMENT_KEY);
        SessionConfig sessionConfig = exchange.getAttachment(SessionConfig.ATTACHMENT_KEY);
        Session session = sm.getSession(exchange, sessionConfig);
        if (session == null) session = sm.createSession(exchange, sessionConfig);
        session.invalidate(exchange);
    }

    public String getURI() {
//        System.out.println("http getURI");
        String host = address;
        if (isHttps) {
            return "https://" + host + ":" + port;
        }
        return "http://" + address + ":" + port;
    }

    private void writeToOutputStream(String content, OutputStream oos) {

        byte[] buf = new byte[8192];
        InputStream is = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
        int c;
        try {
            while ((c = is.read(buf, 0, buf.length)) > 0) {
                oos.write(buf, 0, c);
                oos.flush();
            }
            oos.close();
            is.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
