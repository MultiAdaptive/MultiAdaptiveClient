package node

const (
	MILLISECONDS_OF_DAY    = 1000 * 60 * 60 * 24
	SECONDS_OF_DAY         = 60 * 60 * 24
	SECONDS_OF_LEAP_YEAR   = 60 * 60 * 24 * 366
	SECONDS_OF_COMMON_YEAR = 60 * 60 * 24 * 365
	MINUTES_OF_DAY         = 60 * 24
	MINUTES_OF_LEAP_YEAR   = 60 * 24 * 366
	MINUTES_OF_COMMON_YEAR = 60 * 24 * 365
	SECONDS_OF_MINUTE      = 60
	MILLISECONDS_OF_MINUTE = 1000 * 60
	HOURS_OF_DAY           = 24
	SECONDS_OF_HOUR        = 60 * 60
	DAYS_OF_WEEK           = 7
	WEEKS_OF_YEAR          = 52
	MONTHS_OF_YEAR         = 12
	DAYS_OF_LEAP_YEAR      = 366
	DAYS_OF_COMMON_YEAR    = 365
)

/**
 * 分隔符
 */
const (
	SEPARATOR_SEMICOLON     = ";"
	SEPARATOR_QUESTION_MARK = "?"
	SEPARATOR_COLON         = ":"
	SEPARATOR_COLON2        = "::"
	SEPARATOR_COMMA         = ","
	SEPARATOR_AMPERSAND     = "&"
	SEPARATOR_EQUAL_SIGN    = "="
	SEPARATOR_BLANK         = ""
	SEPARATOR_ASTERISK      = "*"

	/**
	 * 斜线
	 */
	SEPARATOR_VIRGULE = "/"

	/**
	 * 竖线
	 */
	SEPARATOR_VERTICAL_LINE = "|"

	/**
	 * 下划线
	 */
	SEPARATOR_UNDERSCORE = "_"

	/**
	 * 连字符 中横线
	 */
	SEPARATOR_HYPHEN = "-"

	/**
	 * 连字符 艾特
	 */
	SEPARATOR_AT = "@"
)
