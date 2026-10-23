/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.lang;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;

/** Unit test for {@link LangImporter}. */
class LangImporterUnitTest {

    private static final String MSG_SUCCESS = "options.lang.importer.dialog.message.success";
    private static final String MSG_ERROR = "options.lang.importer.dialog.message.error";

    @TempDir Path tempDir;

    private Path installDir;

    @BeforeEach
    void setUp() throws IOException {
        installDir = Files.createDirectories(tempDir.resolve("zap"));
        Files.createDirectories(installDir.resolve(Constant.LANG_DIR));
        Constant.setZapInstall(installDir.toString());
    }

    @Test
    void shouldIncludeMessagesFiles() {
        // Given
        String[] resourceFiles = {
            "Messages.properties",
            "Messages_en.properties",
            "Messages_en_GB.properties",
            "Messages_ar_SA.properties",
            "Messages_fil_PH.properties",
            "Messages_zh_CN.properties",
        };
        // When
        Pattern pattern = LangImporter.createIncludedFilesPattern();
        // Then
        for (String file : resourceFiles) {
            assertThat(file, pattern.matcher(file).matches(), is(equalTo(true)));
        }
    }

    @Test
    void shouldNotMatchOtherFilesThanMessagesFiles() {
        // Given
        String[] resourceFiles = {"OtherFile_ar_SA.properties", "messages.properties"};
        // When
        Pattern pattern = LangImporter.createIncludedFilesPattern();
        // Then
        for (String file : resourceFiles) {
            assertThat(file, pattern.matcher(file).matches(), is(equalTo(false)));
        }
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Messages.properties",
                "lang/Messages_de_DE.properties",
                "./lang/Messages_de_DE.properties",
                "lang/../lang/Messages_de_DE.properties"
            })
    void shouldResolveOutputFileInsideInstallDir(String entryName) {
        // Given / When
        Path outputFile = LangImporter.resolveOutputFile(installDir, entryName);
        // Then
        assertThat(outputFile, is(equalTo(installDir.resolve(entryName).normalize())));
        assertThat(outputFile.startsWith(installDir), is(equalTo(true)));
    }

    @Test
    void shouldResolveAbsoluteEntryNameRelativeToInstallDir() {
        // Given
        String entryName = "/lang/Messages_de_DE.properties";
        // When
        Path outputFile = LangImporter.resolveOutputFile(installDir, entryName);
        // Then
        assertThat(outputFile, is(equalTo(installDir.resolve("lang/Messages_de_DE.properties"))));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "../Messages.properties",
                "../OUTSIDE/Messages.properties",
                "lang/../../OUTSIDE/Messages_de_DE.properties",
                "lang/../../../../../../../../tmp/Messages.properties",
                ".."
            })
    void shouldNotResolveOutputFileOutsideInstallDir(String entryName) {
        // Given / When
        Path outputFile = LangImporter.resolveOutputFile(installDir, entryName);
        // Then
        assertThat(outputFile, is(nullValue()));
    }

    @Test
    void shouldImportMessagesFilesFromLanguagePack() throws Exception {
        // Given
        Path languagePack =
                createLanguagePack(
                        "lang/Messages_de_DE.properties",
                        "Messages_fr_FR.properties",
                        "lang/",
                        "lang/README.txt");
        // When
        String message = LangImporter.importLanguagePack(languagePack.toString());
        // Then
        assertThat(message, is(equalTo(MSG_SUCCESS)));
        assertThat(
                readFile(installDir.resolve("lang/Messages_de_DE.properties")),
                is(equalTo("content of lang/Messages_de_DE.properties")));
        assertThat(
                readFile(installDir.resolve("Messages_fr_FR.properties")),
                is(equalTo("content of Messages_fr_FR.properties")));
        assertThat(Files.exists(installDir.resolve("lang/README.txt")), is(equalTo(false)));
    }

    @Test
    void shouldNotWriteEntriesOutsideInstallDir() throws Exception {
        // Given
        Path outsideDir = Files.createDirectories(tempDir.resolve("OUTSIDE"));
        Path outsideFile = outsideDir.resolve("Messages.properties");
        Files.writeString(outsideFile, "original");
        Path languagePack =
                createLanguagePack(
                        "../OUTSIDE/Messages.properties",
                        "../OUTSIDE/Messages_en_GB.properties",
                        "lang/../../OUTSIDE/Messages_de_DE.properties");
        // When
        String message = LangImporter.importLanguagePack(languagePack.toString());
        // Then
        assertThat(message, is(equalTo(MSG_ERROR)));
        assertThat(readFile(outsideFile), is(equalTo("original")));
        assertThat(Files.exists(outsideDir.resolve("Messages_en_GB.properties")), is(false));
        assertThat(Files.exists(outsideDir.resolve("Messages_de_DE.properties")), is(false));
        assertThat(Files.exists(installDir.resolve("OUTSIDE")), is(false));
    }

    @Test
    void shouldImportValidEntriesAndIgnoreEntriesOutsideInstallDir() throws Exception {
        // Given
        Path outsideDir = Files.createDirectories(tempDir.resolve("OUTSIDE"));
        Path languagePack =
                createLanguagePack(
                        "../OUTSIDE/Messages.properties", "lang/Messages_de_DE.properties");
        // When
        String message = LangImporter.importLanguagePack(languagePack.toString());
        // Then
        assertThat(message, is(equalTo(MSG_SUCCESS)));
        assertThat(Files.exists(outsideDir.resolve("Messages.properties")), is(false));
        assertThat(
                readFile(installDir.resolve("lang/Messages_de_DE.properties")),
                is(equalTo("content of lang/Messages_de_DE.properties")));
    }

    private Path createLanguagePack(String... entryNames) throws IOException {
        Path languagePack = tempDir.resolve("pack.zaplang");
        try (OutputStream os = Files.newOutputStream(languagePack);
                ZipOutputStream zos = new ZipOutputStream(os)) {
            for (String entryName : entryNames) {
                zos.putNextEntry(new ZipEntry(entryName));
                if (!entryName.endsWith("/")) {
                    zos.write(("content of " + entryName).getBytes(StandardCharsets.UTF_8));
                }
                zos.closeEntry();
            }
        }
        return languagePack;
    }

    private static String readFile(Path file) throws IOException {
        return Files.readString(file);
    }
}
