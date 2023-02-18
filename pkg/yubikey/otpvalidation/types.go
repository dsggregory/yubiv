package otpvalidation

type Status int

// nolint
const (
	UNKNOWN_STATUS        Status = iota
	OK                           // The OTP is valid.
	BAD_OTP                      // The OTP is invalid format.
	REPLAYED_OTP                 // The OTP has already been seen by the service.
	BAD_SIGNATURE                // The HMAC signature verification failed.
	MISSING_PARAMETER            // The request lacks a parameter.
	NO_SUCH_CLIENT               // The request id does not exist.
	OPERATION_NOT_ALLOWED        // The request id is not allowed to verify OTPs.
	BACKEND_ERROR                // Unexpected error in our server. Please contact us if you see this error.
	NOT_ENOUGH_ANSWERS           // Server could not get requested number of syncs during before timeout
	REPLAYED_REQUEST             // Server has seen the OTP/Nonce combination before

	CRC_FAILURE
	EMPTY_YUBI_TOKEN  // provided OTP is empty
	UNREGISTERED_USER // Yubikey not registered in database
)

// nolint
var statusStrings = []string{
	"UNKNOWN_STATUS",
	"OK",
	"BAD_OTP",
	"REPLAYED_OTP",
	"BAD_SIGNATURE",
	"MISSING_PARAMETER",
	"NO_SUCH_CLIENT",
	"OPERATION_NOT_ALLOWED",
	"BACKEND_ERROR",
	"NOT_ENOUGH_ANSWERS",
	"REPLAYED_REQUEST",

	"CRC_FAILURE",
	"EMPTY_YUBI_TOKEN",
	"UNREGISTERED_USER",
}

func (s Status) Error() string {
	return s.String()
}

func (s Status) String() string {
	i := int(s)
	if i < 0 || len(statusStrings) <= i {
		i = 0
	}
	return statusStrings[i]
}

// nolint:deadcode
func statusFromString(status string) Status {
	for i, s := range statusStrings {
		if status == s {
			return Status(i)
		}

	}
	return UNKNOWN_STATUS
}

func (s Status) IsError() bool {
	return s == BACKEND_ERROR || s == BAD_OTP || s == BAD_SIGNATURE || s == NO_SUCH_CLIENT || s == MISSING_PARAMETER
}

func (s Status) IsRetryable() bool {
	return s == BAD_OTP || s == NO_SUCH_CLIENT || s == MISSING_PARAMETER
}
