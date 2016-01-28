package org.activehome.api.http;

/*
 * #%L
 * Active Home :: API :: Http
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2016 org.activehome
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


import io.undertow.io.UndertowInputStream;
import io.undertow.server.HttpServerExchange;
import org.kevoree.log.Log;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Jacky Bourgeois
 * @version %I%, %G%
 */
public class HttpHelper {

    public static String readBody(HttpServerExchange exchange) {
        InputStream inputStream = new UndertowInputStream(exchange);
        BufferedReader br = null;
        StringBuilder sb = new StringBuilder();
        String line;
        try {
            br = new BufferedReader(new InputStreamReader(inputStream));
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return sb.toString();
    }

    public static HashMap<String, Object> sendGet(String url, List<String> cookieList) {
        try {
            URL obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();

            //add request header
            con.setRequestProperty("User-Agent", "Mozilla/5.0");
            if (cookieList != null) {
                for (String cookie : cookieList) {
                    Log.info("adding cookie: " + cookie);
                    con.addRequestProperty("Cookie", cookie);
                }
            }

            //Log.info("Sending 'GET' request to URL : " + url);

            HashMap<String, Object> responseMap = new HashMap<>();

            //int responseCode = con.getResponseCode();
            //Log.info("Response code: " + responseCode);
            //Log.info("Response header: ");
            Map<String, List<String>> respHeaderMap = con.getHeaderFields();
            //Log.info("Key : " + entry.getKey() + " ,Value : " + entry.getValue());
            respHeaderMap.entrySet().stream()
                    .filter(entry -> entry.getKey() != null && entry.getKey().compareTo("Set-Cookie") == 0)
                    .forEach(entry -> responseMap.put("Set-Cookie", entry.getValue()));

            responseMap.put("content", inputStreamToString(con.getInputStream()));

            return responseMap;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static HashMap<String, Object> sendPost(String urlStr, String data, List<String> cookieList) {
        try {
            URL url = new URL(urlStr);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();

            //add request header
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-length", String.valueOf(data.length()));
            con.setRequestProperty("User-Agent", "Mozilla/5.0");
            con.setRequestProperty("Accept-Language", "en-UK,en;q=0.5");
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            con.setDoOutput(true);
            if (cookieList != null) {
                for (String cookie : cookieList) {
                    Log.info("adding cookie: " + cookie);
                    con.addRequestProperty("Cookie", cookie);
                }
            }

            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(data);
            wr.flush();
            wr.close();

            // check response
            HashMap<String, Object> responseMap = new HashMap<>();

            int responseCode = con.getResponseCode();
            Log.info("Response code: " + responseCode);
            Log.info("Response header: ");
            Map<String, List<String>> respHeaderMap = con.getHeaderFields();
            for (Map.Entry<String, List<String>> entry : respHeaderMap.entrySet()) {
                Log.info("Key: " + entry.getKey() + " , Value : " + entry.getValue());
                if (entry.getKey() != null && entry.getKey().compareTo("Set-Cookie") == 0) {
                    responseMap.put("Set-Cookie", entry.getValue());
                }
            }

            responseMap.put("content", inputStreamToString(con.getInputStream()));

            return responseMap;
        } catch (IOException e) {
            Log.error(e.getMessage());
        }
        return null;
    }

    public static HashMap<String, Object> sendPostChallenge(String urlStr, String data, List<String> cookieList, String id) {
        try {
            URL url = new URL(urlStr);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();

            //add request header
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-length", String.valueOf(data.length()));
            con.setRequestProperty("User-Agent", "Mozilla/5.0");
            con.setRequestProperty("Accept-Language", "en-UK,en;q=0.5");
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            con.setRequestProperty("Referer", "https://www.epcregister.com/reportSearchAddressSelectAddress.html?id=" + id);
            con.setDoOutput(true);
            con.setInstanceFollowRedirects(false);
            if (cookieList != null) {
                for (String cookie : cookieList) {
                    Log.info("adding cookie: " + cookie);
                    con.addRequestProperty("Cookie", cookie);
                }
            }

            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(data);
            wr.flush();
            wr.close();

            con.connect();
            int status = con.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                if (status == HttpURLConnection.HTTP_MOVED_TEMP
                        || status == HttpURLConnection.HTTP_MOVED_PERM
                        || status == HttpURLConnection.HTTP_SEE_OTHER) {
                    //System.out.println("redirect!");
                    String newUrl = con.getHeaderField("location");
                    String newCookie = con.getHeaderField("Set-Cookie");
                    //System.out.println("New Cookie: "+ newCookie);
                    con = (HttpsURLConnection) new URL(newUrl).openConnection();
                    if (newCookie != null && cookieList != null) cookieList.add(newCookie);

                    //add request header
                    con.setRequestMethod("GET");
                    con.setRequestProperty("User-Agent", "Mozilla/5.0");
                    con.setRequestProperty("Accept-Language", "en-UK,en;q=0.5");
                    if (cookieList != null) {
                        for (String cookie : cookieList) {
                            Log.info("adding cookie: " + cookie);
                            con.addRequestProperty("Cookie", cookie);
                        }
                    }

                    con.connect();
                    status = con.getResponseCode();

                    if (status == HttpURLConnection.HTTP_OK) {
                        // check response
                        HashMap<String, Object> responseMap = new HashMap<>();

                        //int responseCode = con.getResponseCode();
                        //Log.info("Response code: " + responseCode);
                        Log.info("Response header: ");
                        Map<String, List<String>> respHeaderMap = con.getHeaderFields();
                        for (Map.Entry<String, List<String>> entry : respHeaderMap.entrySet()) {
                            Log.info("Key: " + entry.getKey() + " , Value : " + entry.getValue());
                            if (entry.getKey() != null && entry.getKey().compareTo("Set-Cookie") == 0) {
                                responseMap.put("Set-Cookie", entry.getValue());
                            }
                        }

                        responseMap.put("content", inputStreamToString(con.getInputStream()));

                        return responseMap;
                    } else {
                        Log.error("Response error after redirect: " + status);
                    }
                } else {
                    Log.error("Response error, not redirect: " + status);
                }
            } else {
                //System.out.println("status seems ok: " + status);
            }
        } catch (IOException e) {
            Log.error(e.getMessage());
        }
        return null;
    }


    public static String inputStreamToString(InputStream is) {
        BufferedReader in = new BufferedReader(new InputStreamReader(is));
        String inputLine;
        StringBuilder response = new StringBuilder();

        try {
            while ((inputLine = in.readLine()) != null) response.append(inputLine);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return response.toString();
    }

}
