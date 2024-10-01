package logger

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestInitializeDefaultLogger(t *testing.T) {
	logger := InitializeDefaultLogger()

	// Check if the logger is not nil
	if logger == nil {
		t.Errorf("Expected logger to not be nil")
	}

	// Check if the logger has the correct level
	if logger.Level != defaultLogLevel {
		t.Errorf("Expected logger level to be %v but got %v", defaultLogLevel, logger.Level)
	}
}

type formatterTestCase struct {
	format    LogFormat
	expected  logrus.Formatter
	expectErr bool
}

func TestGetFormatter(t *testing.T) {
	testCases := []formatterTestCase{
		{
			format:    logFormatText,
			expected:  &logrus.TextFormatter{ForceColors: true, FullTimestamp: true},
			expectErr: false,
		},
		{
			format:    logFormatJSON,
			expected:  &logrus.JSONFormatter{},
			expectErr: false,
		},
		{
			format:    LogFormat("invalid"),
			expected:  &logrus.TextFormatter{},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		actual, err := getFormatter(tc.format)

		if tc.expectErr {
			if err == nil {
				t.Errorf("Expected error for format '%s' but got no error", string(tc.format))
			} else if err.Error() != fmt.Sprintf("invalid log format '%s'", string(tc.format)) {
				t.Errorf("Expected error message 'invalid log format '%s'' but got '%s'", string(tc.format), err.Error())
			}
		} else {
			if err != nil {
				t.Errorf("Expected no error for format '%s' but got '%s'", string(tc.format), err.Error())
			} else if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Expected formatter '%v' but got '%v'", tc.expected, actual)
			}
		}
	}
}

func TestResetLogOutput(t *testing.T) {
	// Redirect log output to a buffer
	buffer := &bytes.Buffer{}
	DefaultLogger.SetOutput(buffer)

	// Call the function to be tested
	ResetLogOutput()

	// Check if the log output is reset to Stdout
	if DefaultLogger.Out != os.Stdout {
		t.Errorf("Log output not reset to Stdout")
	}
}

func TestGetLogLevel(t *testing.T) {
	expected := logrus.InfoLevel
	actual := GetLogLevel()

	if actual != expected {
		t.Errorf("Expected log level to be %v, but got %v", expected, actual)
	}
}

func TestSetLogLevel(t *testing.T) {
	// Set the log level to debug
	logLevel := logrus.DebugLevel
	SetLogLevel(logLevel)

	// Get the current log level
	currentLogLevel := DefaultLogger.Level

	// Check if the current log level is equal to the set log level
	if currentLogLevel != logLevel {
		t.Errorf("Expected log level %v, but got %v", logLevel, currentLogLevel)
	}
}

func TestSetLogLevelToDebug(t *testing.T) {
	// Save the original log level
	originalLevel := DefaultLogger.Level

	// Set the log level to debug
	setLogLevelToDebug()

	// Check if the log level is now debug
	if DefaultLogger.Level != logrus.DebugLevel {
		t.Errorf("Expected log level to be debug, but got %v", DefaultLogger.Level)
	}

	// Restore the original log level
	DefaultLogger.SetLevel(originalLevel)
}

func TestSetLogFormat(t *testing.T) {
	// Test case 1: Valid log format
	setLogFormat("json")

	// Assert that the formatter is set correctly
	ret := fmt.Sprintf("%+v", reflect.TypeOf(DefaultLogger.Formatter))
	assert.Equal(t, "*logrus.JSONFormatter", ret)
}

func TestPopulateLogOpts(t *testing.T) {
	t.Run("ValidLevel", func(t *testing.T) {
		o := LogOptions{}
		level := "debug"
		format := "text"

		PopulateLogOpts(o, level, format)

		if o[levelOpt] != level {
			t.Errorf("Expected log level '%s', but got '%s'", level, o[levelOpt])
		}
	})

	t.Run("InvalidLevel", func(t *testing.T) {
		o := LogOptions{}
		level := "invalid"
		format := "text"

		PopulateLogOpts(o, level, format)

		if _, ok := o[levelOpt]; ok {
			t.Errorf("Expected log level option to be ignored, but it is present")
		}
	})

	t.Run("ValidFormat", func(t *testing.T) {
		o := LogOptions{}
		level := "info"
		format := "json"

		PopulateLogOpts(o, level, format)

		if o[formatOpt] != string(logFormatJSON) {
			t.Errorf("Expected log format '%s', but got '%s'", logFormatJSON, o[formatOpt])
		}
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		o := LogOptions{}
		level := "info"
		format := "xml"

		PopulateLogOpts(o, level, format)

		if _, ok := o[formatOpt]; ok {
			t.Errorf("Expected log format option to be ignored, but it is present")
		}
	})
}

func TestSetupLogging(t *testing.T) {
	// Test case 1: debug is true
	t.Run("Debug is true", func(t *testing.T) {
		o := LogOptions{
			"LogFormat": "text",
			"LogLevel":  "info",
		}
		debug := true

		err := SetupLogging(o, debug)
		if err != nil {
			t.Errorf("Expected nil error, but got %v", err)
		}

		// Verify log level, DefaultLogger changed to debug
		expectedLogLevel := logrus.DebugLevel
		if DefaultLogger.GetLevel() != expectedLogLevel {
			t.Errorf("Expected log level to be %v, but got %v", expectedLogLevel, logrus.GetLevel())
		}
	})

	// Test case 2: debug is false
	t.Run("Debug is false", func(t *testing.T) {
		o := LogOptions{
			"LogFormat": "json",
			"LogLevel":  "warning",
		}
		debug := false

		err := SetupLogging(o, debug)
		if err != nil {
			t.Errorf("Expected nil error, but got %v", err)
		}

		// Verify log level, SetupLogging should not do any changes, still use o setting.
		expectedLogLevel := o.getLogLevel()
		if DefaultLogger.GetLevel() != expectedLogLevel {
			t.Errorf("Expected log level to be %v, but got %v", expectedLogLevel, logrus.GetLevel())
		}
	})
}

func TestGetLogger(t *testing.T) {
	// Setup
	expectedLogger := logrus.New()

	// Mock the DefaultLogger
	oldDefaultLogger := DefaultLogger
	DefaultLogger = expectedLogger

	// Execute
	actualLogger := GetLogger()

	// Verify
	assert.Equal(t, expectedLogger, actualLogger)

	// Restore the DefaultLogger
	DefaultLogger = oldDefaultLogger
}
