package log

import (
	"io"
	"log"
	"os"
)

var Log *log.Logger

func InitLog(outFile string) {
	Log = log.New(os.Stderr, "", log.LstdFlags)

	if outFile != "" {
		logFile, err := os.OpenFile(outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			Log.Fatalf("[-] Error opening log file: %v", err)
		}

		multiWriter := io.MultiWriter(os.Stderr, logFile)
		Log.SetOutput(multiWriter)
	}
}
