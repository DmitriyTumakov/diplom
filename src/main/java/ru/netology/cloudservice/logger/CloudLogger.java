package ru.netology.cloudservice.logger;

import java.io.IOException;

public interface CloudLogger {
    public void log(String message, LogType type, boolean append) throws IOException;
}
