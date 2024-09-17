package ru.netology.cloudservice.logger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;

public class CloudLoggerImpl implements CloudLogger {
    private final File log = new File("log.txt");

    @Override
    public void log(String message, LogType type, boolean append) {
        if (log.exists()) {
            try (FileOutputStream fos = new FileOutputStream(log, append)) {
                fos.write(("[" + LocalDateTime.now() + "] | " + type + " | " + message + '\n').getBytes());
            } catch (IOException e) {
                log(e.getMessage(), LogType.ERROR, true);
            }
        } else {
            try {
                if (log.createNewFile()) {
                    log(message, type, false);
                }
            } catch (IOException e) {
                log(e.getMessage(), LogType.ERROR, true);
            }
        }
    }
}
