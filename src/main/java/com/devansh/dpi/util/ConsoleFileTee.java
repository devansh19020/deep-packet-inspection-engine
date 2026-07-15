
package com.devansh.dpi.util;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class ConsoleFileTee implements AutoCloseable {

    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;

    private final PrintStream fileStream;
    private final PrintStream teeOut;
    private final PrintStream teeErr;

    public ConsoleFileTee(Path reportPath) throws IOException {
        Path absolutePath = reportPath.toAbsolutePath();
        Files.createDirectories(absolutePath.getParent());

        fileStream = new PrintStream(
                Files.newOutputStream(absolutePath),
                true,
                StandardCharsets.UTF_8
        );

        teeOut = new PrintStream(
                new TeeOutputStream(originalOut, fileStream),
                true,
                StandardCharsets.UTF_8
        );

        teeErr = new PrintStream(
                new TeeOutputStream(originalErr, fileStream),
                true,
                StandardCharsets.UTF_8
        );

        System.setOut(teeOut);
        System.setErr(teeErr);
    }

    private static class TeeOutputStream extends OutputStream {

        private final OutputStream console;
        private final PrintStream file;

        TeeOutputStream(OutputStream console, PrintStream file) {
            this.console = console;
            this.file = file;
        }

        @Override
        public void write(int value) throws IOException {
            console.write(value);

            synchronized (file) {
                file.write(value);
            }
        }

        @Override
        public void write(byte[] data, int offset, int length)
                throws IOException {
            console.write(data, offset, length);

            synchronized (file) {
                file.write(data, offset, length);
            }
        }

        @Override
        public void flush() throws IOException {
            console.flush();

            synchronized (file) {
                file.flush();
            }
        }

        @Override
        public void close() throws IOException {
            // Do not close the original console or shared file stream here.
            flush();
        }
    }

    @Override
    public void close() {
        System.setOut(originalOut);
        System.setErr(originalErr);

        teeOut.flush();
        teeErr.flush();

        teeOut.close();
        teeErr.close();

        fileStream.close();
    }
}
