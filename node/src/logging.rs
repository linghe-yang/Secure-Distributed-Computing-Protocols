//! Plain, timestamped log lines using the same UTC logger as HashRand.
use log::{LevelFilter, Log, Metadata, Record, SetLoggerError};
use simple_logger::SimpleLogger;

struct LineLogger(SimpleLogger);
impl Log for LineLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.0.enabled(metadata)
    }
    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // Preserve separate diagnostic lines, giving each one its own timestamp.
        let message = record.args().to_string().replace('\r', "\\r");
        for line in message.split('\n') {
            self.0.log(
                &Record::builder()
                    .args(format_args!("{}", line))
                    .level(record.level())
                    .target(record.target())
                    .module_path(record.module_path())
                    .file(record.file())
                    .line(record.line())
                    .build(),
            );
        }
    }
    fn flush(&self) {
        self.0.flush();
    }
}
pub fn init(level: LevelFilter) -> Result<(), SetLoggerError> {
    let logger = SimpleLogger::new()
        .with_level(level)
        .with_utc_timestamps()
        .with_colors(false);
    log::set_boxed_logger(Box::new(LineLogger(logger)))?;
    log::set_max_level(level);
    Ok(())
}
