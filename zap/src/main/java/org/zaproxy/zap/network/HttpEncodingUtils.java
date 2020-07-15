/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.network;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

public class HttpEncodingUtils {

    private static final Logger LOG = Logger.getLogger(HttpEncodingUtils.class);

    private static FilterInputStream buildStreamDecoder(String encoding, ByteArrayInputStream bais)
            throws IOException {
        if (encoding.equalsIgnoreCase(HttpHeader.DEFLATE)) {
            return new InflaterInputStream(bais, new Inflater(true));
        } else {
            return new GZIPInputStream(bais);
        }
    }

    public static void decodeResponseIfNeeded(HttpMessage msg) {
        String encoding = msg.getResponseHeader().getHeader(HttpHeader.CONTENT_ENCODING);
        LOG.info("SBSB encoding: " + encoding); // TODO
        if (encoding != null && !encoding.equalsIgnoreCase(HttpHeader.IDENTITY)) {
            encoding =
                    Pattern.compile("^x-", Pattern.CASE_INSENSITIVE)
                            .matcher(encoding)
                            .replaceAll("");
            if (!encoding.equalsIgnoreCase(HttpHeader.DEFLATE)
                    && !encoding.equalsIgnoreCase(HttpHeader.GZIP)) {
                LOG.warn("Unsupported content encoding method: " + encoding);
                return;
            }
            // Uncompress content
            try (ByteArrayInputStream bais =
                            new ByteArrayInputStream(msg.getResponseBody().getBytes());
                    FilterInputStream fis = buildStreamDecoder(encoding, bais);
                    BufferedInputStream bis = new BufferedInputStream(fis);
                    ByteArrayOutputStream out = new ByteArrayOutputStream(); ) {
                int readLength;
                byte[] readBuffer = new byte[1024];
                while ((readLength = bis.read(readBuffer, 0, 1024)) != -1) {
                    out.write(readBuffer, 0, readLength);
                }
                msg.setResponseBody(out.toByteArray());
                msg.getResponseHeader().setHeader(HttpHeader.CONTENT_ENCODING, null);
                if (msg.getResponseHeader().getHeader(HttpHeader.CONTENT_LENGTH) != null) {
                    msg.getResponseHeader()
                            .setHeader(HttpHeader.CONTENT_LENGTH, Integer.toString(out.size()));
                }
                LOG.info("SBSB decoded!"); // TODO
            } catch (IOException e) {
                LOG.error("Unable to uncompress gzip content: " + e.getMessage(), e);
            }
        }
    }
}
