import winston from 'winston';

let loggerInstance: winston.Logger | undefined;

export function getLogger(level = 'info'): winston.Logger {
  if (!loggerInstance) {
    loggerInstance = winston.createLogger({
      level,
      format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.printf(
          ({ timestamp, level, message }) => `${timestamp} [${level.toUpperCase()}] ${message}`,
        ),
      ),
      transports: [new winston.transports.Console()],
    });
  }
  return loggerInstance;
}
