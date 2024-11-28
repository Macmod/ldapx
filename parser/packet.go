package parser

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

/*
	Code adapted from https://github.com/go-ldap/ldap (MIT License)
*/

// LDAP Application Codes
const (
	ApplicationBindRequest           = 0
	ApplicationBindResponse          = 1
	ApplicationUnbindRequest         = 2
	ApplicationSearchRequest         = 3
	ApplicationSearchResultEntry     = 4
	ApplicationSearchResultDone      = 5
	ApplicationModifyRequest         = 6
	ApplicationModifyResponse        = 7
	ApplicationAddRequest            = 8
	ApplicationAddResponse           = 9
	ApplicationDelRequest            = 10
	ApplicationDelResponse           = 11
	ApplicationModifyDNRequest       = 12
	ApplicationModifyDNResponse      = 13
	ApplicationCompareRequest        = 14
	ApplicationCompareResponse       = 15
	ApplicationAbandonRequest        = 16
	ApplicationSearchResultReference = 19
	ApplicationExtendedRequest       = 23
	ApplicationExtendedResponse      = 24
	ApplicationIntermediateResponse  = 25
)

// ApplicationMap contains human readable descriptions of LDAP Application Codes
var ApplicationMap = map[uint8]string{
	ApplicationBindRequest:           "Bind Request",
	ApplicationBindResponse:          "Bind Response",
	ApplicationUnbindRequest:         "Unbind Request",
	ApplicationSearchRequest:         "Search Request",
	ApplicationSearchResultEntry:     "Search Result Entry",
	ApplicationSearchResultDone:      "Search Result Done",
	ApplicationModifyRequest:         "Modify Request",
	ApplicationModifyResponse:        "Modify Response",
	ApplicationAddRequest:            "Add Request",
	ApplicationAddResponse:           "Add Response",
	ApplicationDelRequest:            "Del Request",
	ApplicationDelResponse:           "Del Response",
	ApplicationModifyDNRequest:       "Modify DN Request",
	ApplicationModifyDNResponse:      "Modify DN Response",
	ApplicationCompareRequest:        "Compare Request",
	ApplicationCompareResponse:       "Compare Response",
	ApplicationAbandonRequest:        "Abandon Request",
	ApplicationSearchResultReference: "Search Result Reference",
	ApplicationExtendedRequest:       "Extended Request",
	ApplicationExtendedResponse:      "Extended Response",
	ApplicationIntermediateResponse:  "Intermediate Response",
}

const (
	// ControlTypePaging - https://www.ietf.org/rfc/rfc2696.txt
	ControlTypePaging = "1.2.840.113556.1.4.319"
	// ControlTypeBeheraPasswordPolicy - https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
	ControlTypeBeheraPasswordPolicy = "1.3.6.1.4.1.42.2.27.8.5.1"
	// ControlTypeVChuPasswordMustChange - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	ControlTypeVChuPasswordMustChange = "2.16.840.1.113730.3.4.4"
	// ControlTypeVChuPasswordWarning - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	ControlTypeVChuPasswordWarning = "2.16.840.1.113730.3.4.5"
	// ControlTypeManageDsaIT - https://tools.ietf.org/html/rfc3296
	ControlTypeManageDsaIT = "2.16.840.1.113730.3.4.2"
	// ControlTypeWhoAmI - https://tools.ietf.org/html/rfc4532
	ControlTypeWhoAmI = "1.3.6.1.4.1.4203.1.11.3"
	// ControlTypeSubtreeDelete - https://datatracker.ietf.org/doc/html/draft-armijo-ldap-treedelete-02
	ControlTypeSubtreeDelete = "1.2.840.113556.1.4.805"

	// ControlTypeServerSideSorting - https://www.ietf.org/rfc/rfc2891.txt
	ControlTypeServerSideSorting = "1.2.840.113556.1.4.473"
	// ControlTypeServerSideSorting - https://www.ietf.org/rfc/rfc2891.txt
	ControlTypeServerSideSortingResult = "1.2.840.113556.1.4.474"

	// ControlTypeMicrosoftNotification - https://msdn.microsoft.com/en-us/library/aa366983(v=vs.85).aspx
	ControlTypeMicrosoftNotification = "1.2.840.113556.1.4.528"
	// ControlTypeMicrosoftShowDeleted - https://msdn.microsoft.com/en-us/library/aa366989(v=vs.85).aspx
	ControlTypeMicrosoftShowDeleted = "1.2.840.113556.1.4.417"
	// ControlTypeMicrosoftServerLinkTTL - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f4f523a8-abc0-4b3a-a471-6b2fef135481?redirectedfrom=MSDN
	ControlTypeMicrosoftServerLinkTTL = "1.2.840.113556.1.4.2309"
	// ControlTypeDirSync - Active Directory DirSync - https://msdn.microsoft.com/en-us/library/aa366978(v=vs.85).aspx
	ControlTypeDirSync = "1.2.840.113556.1.4.841"

	// ControlTypeSyncRequest - https://www.ietf.org/rfc/rfc4533.txt
	ControlTypeSyncRequest = "1.3.6.1.4.1.4203.1.9.1.1"
	// ControlTypeSyncState - https://www.ietf.org/rfc/rfc4533.txt
	ControlTypeSyncState = "1.3.6.1.4.1.4203.1.9.1.2"
	// ControlTypeSyncDone - https://www.ietf.org/rfc/rfc4533.txt
	ControlTypeSyncDone = "1.3.6.1.4.1.4203.1.9.1.3"
	// ControlTypeSyncInfo - https://www.ietf.org/rfc/rfc4533.txt
	ControlTypeSyncInfo = "1.3.6.1.4.1.4203.1.9.1.4"
)

// ControlTypeMap maps controls to text descriptions
var ControlTypeMap = map[string]string{
	ControlTypePaging:                  "Paging",
	ControlTypeBeheraPasswordPolicy:    "Password Policy - Behera Draft",
	ControlTypeManageDsaIT:             "Manage DSA IT",
	ControlTypeSubtreeDelete:           "Subtree Delete Control",
	ControlTypeMicrosoftNotification:   "Change Notification - Microsoft",
	ControlTypeMicrosoftShowDeleted:    "Show Deleted Objects - Microsoft",
	ControlTypeMicrosoftServerLinkTTL:  "Return TTL-DNs for link values with associated expiry times - Microsoft",
	ControlTypeServerSideSorting:       "Server Side Sorting Request - LDAP Control Extension for Server Side Sorting of Search Results (RFC2891)",
	ControlTypeServerSideSortingResult: "Server Side Sorting Results - LDAP Control Extension for Server Side Sorting of Search Results (RFC2891)",
	ControlTypeDirSync:                 "DirSync",
	ControlTypeSyncRequest:             "Sync Request",
	ControlTypeSyncState:               "Sync State",
	ControlTypeSyncDone:                "Sync Done",
	ControlTypeSyncInfo:                "Sync Info",
}

// LDAP Result Codes
const (
	LDAPResultSuccess                            = 0
	LDAPResultOperationsError                    = 1
	LDAPResultProtocolError                      = 2
	LDAPResultTimeLimitExceeded                  = 3
	LDAPResultSizeLimitExceeded                  = 4
	LDAPResultCompareFalse                       = 5
	LDAPResultCompareTrue                        = 6
	LDAPResultAuthMethodNotSupported             = 7
	LDAPResultStrongAuthRequired                 = 8
	LDAPResultReferral                           = 10
	LDAPResultAdminLimitExceeded                 = 11
	LDAPResultUnavailableCriticalExtension       = 12
	LDAPResultConfidentialityRequired            = 13
	LDAPResultSaslBindInProgress                 = 14
	LDAPResultNoSuchAttribute                    = 16
	LDAPResultUndefinedAttributeType             = 17
	LDAPResultInappropriateMatching              = 18
	LDAPResultConstraintViolation                = 19
	LDAPResultAttributeOrValueExists             = 20
	LDAPResultInvalidAttributeSyntax             = 21
	LDAPResultNoSuchObject                       = 32
	LDAPResultAliasProblem                       = 33
	LDAPResultInvalidDNSyntax                    = 34
	LDAPResultIsLeaf                             = 35
	LDAPResultAliasDereferencingProblem          = 36
	LDAPResultInappropriateAuthentication        = 48
	LDAPResultInvalidCredentials                 = 49
	LDAPResultInsufficientAccessRights           = 50
	LDAPResultBusy                               = 51
	LDAPResultUnavailable                        = 52
	LDAPResultUnwillingToPerform                 = 53
	LDAPResultLoopDetect                         = 54
	LDAPResultSortControlMissing                 = 60
	LDAPResultOffsetRangeError                   = 61
	LDAPResultNamingViolation                    = 64
	LDAPResultObjectClassViolation               = 65
	LDAPResultNotAllowedOnNonLeaf                = 66
	LDAPResultNotAllowedOnRDN                    = 67
	LDAPResultEntryAlreadyExists                 = 68
	LDAPResultObjectClassModsProhibited          = 69
	LDAPResultResultsTooLarge                    = 70
	LDAPResultAffectsMultipleDSAs                = 71
	LDAPResultVirtualListViewErrorOrControlError = 76
	LDAPResultOther                              = 80
	LDAPResultServerDown                         = 81
	LDAPResultLocalError                         = 82
	LDAPResultEncodingError                      = 83
	LDAPResultDecodingError                      = 84
	LDAPResultTimeout                            = 85
	LDAPResultAuthUnknown                        = 86
	LDAPResultFilterError                        = 87
	LDAPResultUserCanceled                       = 88
	LDAPResultParamError                         = 89
	LDAPResultNoMemory                           = 90
	LDAPResultConnectError                       = 91
	LDAPResultNotSupported                       = 92
	LDAPResultControlNotFound                    = 93
	LDAPResultNoResultsReturned                  = 94
	LDAPResultMoreResultsToReturn                = 95
	LDAPResultClientLoop                         = 96
	LDAPResultReferralLimitExceeded              = 97
	LDAPResultInvalidResponse                    = 100
	LDAPResultAmbiguousResponse                  = 101
	LDAPResultTLSNotSupported                    = 112
	LDAPResultIntermediateResponse               = 113
	LDAPResultUnknownType                        = 114
	LDAPResultCanceled                           = 118
	LDAPResultNoSuchOperation                    = 119
	LDAPResultTooLate                            = 120
	LDAPResultCannotCancel                       = 121
	LDAPResultAssertionFailed                    = 122
	LDAPResultAuthorizationDenied                = 123
	LDAPResultSyncRefreshRequired                = 4096

	ErrorNetwork            = 200
	ErrorFilterCompile      = 201
	ErrorFilterDecompile    = 202
	ErrorDebugging          = 203
	ErrorUnexpectedMessage  = 204
	ErrorUnexpectedResponse = 205
	ErrorEmptyPassword      = 206
)

// LDAPResultCodeMap contains string descriptions for LDAP error codes
var LDAPResultCodeMap = map[uint16]string{
	LDAPResultSuccess:                            "Success",
	LDAPResultOperationsError:                    "Operations Error",
	LDAPResultProtocolError:                      "Protocol Error",
	LDAPResultTimeLimitExceeded:                  "Time Limit Exceeded",
	LDAPResultSizeLimitExceeded:                  "Size Limit Exceeded",
	LDAPResultCompareFalse:                       "Compare False",
	LDAPResultCompareTrue:                        "Compare True",
	LDAPResultAuthMethodNotSupported:             "Auth Method Not Supported",
	LDAPResultStrongAuthRequired:                 "Strong Auth Required",
	LDAPResultReferral:                           "Referral",
	LDAPResultAdminLimitExceeded:                 "Admin Limit Exceeded",
	LDAPResultUnavailableCriticalExtension:       "Unavailable Critical Extension",
	LDAPResultConfidentialityRequired:            "Confidentiality Required",
	LDAPResultSaslBindInProgress:                 "Sasl Bind In Progress",
	LDAPResultNoSuchAttribute:                    "No Such Attribute",
	LDAPResultUndefinedAttributeType:             "Undefined Attribute Type",
	LDAPResultInappropriateMatching:              "Inappropriate Matching",
	LDAPResultConstraintViolation:                "Constraint Violation",
	LDAPResultAttributeOrValueExists:             "Attribute Or Value Exists",
	LDAPResultInvalidAttributeSyntax:             "Invalid Attribute Syntax",
	LDAPResultNoSuchObject:                       "No Such Object",
	LDAPResultAliasProblem:                       "Alias Problem",
	LDAPResultInvalidDNSyntax:                    "Invalid DN Syntax",
	LDAPResultIsLeaf:                             "Is Leaf",
	LDAPResultAliasDereferencingProblem:          "Alias Dereferencing Problem",
	LDAPResultInappropriateAuthentication:        "Inappropriate Authentication",
	LDAPResultInvalidCredentials:                 "Invalid Credentials",
	LDAPResultInsufficientAccessRights:           "Insufficient Access Rights",
	LDAPResultBusy:                               "Busy",
	LDAPResultUnavailable:                        "Unavailable",
	LDAPResultUnwillingToPerform:                 "Unwilling To Perform",
	LDAPResultLoopDetect:                         "Loop Detect",
	LDAPResultSortControlMissing:                 "Sort Control Missing",
	LDAPResultOffsetRangeError:                   "Result Offset Range Error",
	LDAPResultNamingViolation:                    "Naming Violation",
	LDAPResultObjectClassViolation:               "Object Class Violation",
	LDAPResultResultsTooLarge:                    "Results Too Large",
	LDAPResultNotAllowedOnNonLeaf:                "Not Allowed On Non Leaf",
	LDAPResultNotAllowedOnRDN:                    "Not Allowed On RDN",
	LDAPResultEntryAlreadyExists:                 "Entry Already Exists",
	LDAPResultObjectClassModsProhibited:          "Object Class Mods Prohibited",
	LDAPResultAffectsMultipleDSAs:                "Affects Multiple DSAs",
	LDAPResultVirtualListViewErrorOrControlError: "Failed because of a problem related to the virtual list view",
	LDAPResultOther:                              "Other",
	LDAPResultServerDown:                         "Cannot establish a connection",
	LDAPResultLocalError:                         "An error occurred",
	LDAPResultEncodingError:                      "LDAP encountered an error while encoding",
	LDAPResultDecodingError:                      "LDAP encountered an error while decoding",
	LDAPResultTimeout:                            "LDAP timeout while waiting for a response from the server",
	LDAPResultAuthUnknown:                        "The auth method requested in a bind request is unknown",
	LDAPResultFilterError:                        "An error occurred while encoding the given search filter",
	LDAPResultUserCanceled:                       "The user canceled the operation",
	LDAPResultParamError:                         "An invalid parameter was specified",
	LDAPResultNoMemory:                           "Out of memory error",
	LDAPResultConnectError:                       "A connection to the server could not be established",
	LDAPResultNotSupported:                       "An attempt has been made to use a feature not supported LDAP",
	LDAPResultControlNotFound:                    "The controls required to perform the requested operation were not found",
	LDAPResultNoResultsReturned:                  "No results were returned from the server",
	LDAPResultMoreResultsToReturn:                "There are more results in the chain of results",
	LDAPResultClientLoop:                         "A loop has been detected. For example when following referrals",
	LDAPResultReferralLimitExceeded:              "The referral hop limit has been exceeded",
	LDAPResultCanceled:                           "Operation was canceled",
	LDAPResultNoSuchOperation:                    "Server has no knowledge of the operation requested for cancellation",
	LDAPResultTooLate:                            "Too late to cancel the outstanding operation",
	LDAPResultCannotCancel:                       "The identified operation does not support cancellation or the cancel operation cannot be performed",
	LDAPResultAssertionFailed:                    "An assertion control given in the LDAP operation evaluated to false causing the operation to not be performed",
	LDAPResultSyncRefreshRequired:                "Refresh Required",
	LDAPResultInvalidResponse:                    "Invalid Response",
	LDAPResultAmbiguousResponse:                  "Ambiguous Response",
	LDAPResultTLSNotSupported:                    "Tls Not Supported",
	LDAPResultIntermediateResponse:               "Intermediate Response",
	LDAPResultUnknownType:                        "Unknown Type",
	LDAPResultAuthorizationDenied:                "Authorization Denied",

	ErrorNetwork:            "Network Error",
	ErrorFilterCompile:      "Filter Compile Error",
	ErrorFilterDecompile:    "Filter Decompile Error",
	ErrorDebugging:          "Debugging Error",
	ErrorUnexpectedMessage:  "Unexpected Message",
	ErrorUnexpectedResponse: "Unexpected Response",
	ErrorEmptyPassword:      "Empty password not allowed by the client",
}

// Error holds LDAP error information
type Error struct {
	// Err is the underlying error
	Err error
	// ResultCode is the LDAP error code
	ResultCode uint16
	// MatchedDN is the matchedDN returned if any
	MatchedDN string
	// Packet is the returned packet if any
	Packet *ber.Packet
}

func (e *Error) Error() string {
	return fmt.Sprintf("LDAP Result Code %d %q: %s", e.ResultCode, LDAPResultCodeMap[e.ResultCode], e.Err.Error())
}

func (e *Error) Unwrap() error { return e.Err }

// GetLDAPError creates an Error out of a BER packet representing a LDAPResult
// The return is an error object. It can be casted to a Error structure.
// This function returns nil if resultCode in the LDAPResult sequence is success(0).
func GetLDAPError(packet *ber.Packet) error {
	if packet == nil {
		return &Error{ResultCode: ErrorUnexpectedResponse, Err: fmt.Errorf("Empty packet")}
	}

	if len(packet.Children) >= 2 {
		response := packet.Children[1]
		if response == nil {
			return &Error{ResultCode: ErrorUnexpectedResponse, Err: fmt.Errorf("Empty response in packet"), Packet: packet}
		}
		if response.ClassType == ber.ClassApplication && response.TagType == ber.TypeConstructed && len(response.Children) >= 3 {
			if ber.Type(response.Children[0].Tag) == ber.Type(ber.TagInteger) || ber.Type(response.Children[0].Tag) == ber.Type(ber.TagEnumerated) {
				resultCode := uint16(response.Children[0].Value.(int64))
				if resultCode == 0 { // No error
					return nil
				}

				if ber.Type(response.Children[1].Tag) == ber.Type(ber.TagOctetString) &&
					ber.Type(response.Children[2].Tag) == ber.Type(ber.TagOctetString) {
					return &Error{
						ResultCode: resultCode,
						MatchedDN:  response.Children[1].Value.(string),
						Err:        fmt.Errorf("%v", response.Children[2].Value),
						Packet:     packet,
					}
				}
			}
		}
	}

	return &Error{ResultCode: ErrorNetwork, Err: fmt.Errorf("Invalid packet format"), Packet: packet}
}

// NewError creates an LDAP error with the given code and underlying error
func NewError(resultCode uint16, err error) error {
	return &Error{ResultCode: resultCode, Err: err}
}

/*
func AddDefaultLDAPResponseDescriptions(packet *ber.Packet) error {
	resultCode := uint16(LDAPResultSuccess)
	matchedDN := ""
	description := "Success"
	if err := GetLDAPError(packet); err != nil {
		resultCode = err.(*Error).ResultCode
		matchedDN = err.(*Error).MatchedDN
		description = "Error Message"
	}

	packet.Children[1].Children[0].Description = "Result Code (" + LDAPResultCodeMap[resultCode] + ")"
	packet.Children[1].Children[1].Description = "Matched DN (" + matchedDN + ")"
	packet.Children[1].Children[2].Description = description
	if len(packet.Children[1].Children) > 3 {
		packet.Children[1].Children[3].Description = "Referral"
	}
	if len(packet.Children) == 3 {
		return AddControlDescriptions(packet.Children[2])
	}
	return nil
}

// Adds descriptions to an LDAP Response packet for debugging
func AddLDAPDescriptions(packet *ber.Packet) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = NewError(ErrorDebugging, fmt.Errorf("ldap: cannot process packet to Add descriptions: %s", r))
		}
	}()
	packet.Description = "LDAP Response"
	packet.Children[0].Description = "Message ID"

	application := uint8(packet.Children[1].Tag)
	packet.Children[1].Description = ApplicationMap[application]

	switch application {
	case ApplicationBindRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationBindResponse:
		err = AddDefaultLDAPResponseDescriptions(packet)
	case ApplicationUnbindRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationSearchRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationSearchResultEntry:
		packet.Children[1].Children[0].Description = "Object Name"
		packet.Children[1].Children[1].Description = "Attributes"
		for _, child := range packet.Children[1].Children[1].Children {
			child.Description = "Attribute"
			child.Children[0].Description = "Attribute Name"
			child.Children[1].Description = "Attribute Values"
			for _, grandchild := range child.Children[1].Children {
				grandchild.Description = "Attribute Value"
			}
		}
		if len(packet.Children) == 3 {
			err = AddControlDescriptions(packet.Children[2])
		}
	case ApplicationSearchResultDone:
		err = AddDefaultLDAPResponseDescriptions(packet)
	case ApplicationModifyRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationModifyResponse:
	case ApplicationAddRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationAddResponse:
	case ApplicationDelRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationDelResponse:
	case ApplicationModifyDNRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationModifyDNResponse:
	case ApplicationCompareRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationCompareResponse:
	case ApplicationAbandonRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationSearchResultReference:
	case ApplicationExtendedRequest:
		err = AddRequestDescriptions(packet)
	case ApplicationExtendedResponse:
	}

	return err
}

func AddRequestDescriptions(packet *ber.Packet) error {
	packet.Description = "LDAP Request"
	packet.Children[0].Description = "Message ID"
	packet.Children[1].Description = ApplicationMap[uint8(packet.Children[1].Tag)]
	if len(packet.Children) == 3 {
		return AddControlDescriptions(packet.Children[2])
	}
	return nil
}

func AddControlDescriptions(packet *ber.Packet) error {
	packet.Description = "Controls"
	for _, child := range packet.Children {
		var value *ber.Packet
		controlType := ""
		child.Description = "Control"
		switch len(child.Children) {
		case 0:
			// at least one child is required for control type
			return fmt.Errorf("at least one child is required for control type")

		case 1:
			// just type, no criticality or value
			controlType = child.Children[0].Value.(string)
			child.Children[0].Description = "Control Type (" + ControlTypeMap[controlType] + ")"

		case 2:
			controlType = child.Children[0].Value.(string)
			child.Children[0].Description = "Control Type (" + ControlTypeMap[controlType] + ")"
			// Children[1] could be criticality or value (both are optional)
			// duck-type on whether this is a boolean
			if _, ok := child.Children[1].Value.(bool); ok {
				child.Children[1].Description = "Criticality"
			} else {
				child.Children[1].Description = "Control Value"
				value = child.Children[1]
			}

		case 3:
			// criticality and value present
			controlType = child.Children[0].Value.(string)
			child.Children[0].Description = "Control Type (" + ControlTypeMap[controlType] + ")"
			child.Children[1].Description = "Criticality"
			child.Children[2].Description = "Control Value"
			value = child.Children[2]

		default:
			// more than 3 children is invalid
			return fmt.Errorf("more than 3 children for control packet found")
		}

		if value == nil {
			continue
		}
		switch controlType {
		case ControlTypePaging:
			value.Description += " (Paging)"
			if value.Value != nil {
				valueChildren, err := ber.DecodePacketErr(value.Data.Bytes())
				if err != nil {
					return fmt.Errorf("failed to decode data bytes: %s", err)
				}
				value.Data.Truncate(0)
				value.Value = nil
				valueChildren.Children[1].Value = valueChildren.Children[1].Data.Bytes()
				value.AppendChild(valueChildren)
			}
			value.Children[0].Description = "Real Search Control Value"
			value.Children[0].Children[0].Description = "Paging Size"
			value.Children[0].Children[1].Description = "Cookie"

		case ControlTypeBeheraPasswordPolicy:
			value.Description += " (Password Policy - Behera Draft)"
			if value.Value != nil {
				valueChildren, err := ber.DecodePacketErr(value.Data.Bytes())
				if err != nil {
					return fmt.Errorf("failed to decode data bytes: %s", err)
				}
				value.Data.Truncate(0)
				value.Value = nil
				value.AppendChild(valueChildren)
			}
			sequence := value.Children[0]
			for _, child := range sequence.Children {
				if child.Tag == 0 {
					// Warning
					warningPacket := child.Children[0]
					val, err := ber.ParseInt64(warningPacket.Data.Bytes())
					if err != nil {
						return fmt.Errorf("failed to decode data bytes: %s", err)
					}
					if warningPacket.Tag == 0 {
						// timeBeforeExpiration
						value.Description += " (TimeBeforeExpiration)"
						warningPacket.Value = val
					} else if warningPacket.Tag == 1 {
						// graceAuthNsRemaining
						value.Description += " (GraceAuthNsRemaining)"
						warningPacket.Value = val
					}
				} else if child.Tag == 1 {
					// Error
					bs := child.Data.Bytes()
					if len(bs) != 1 || bs[0] > 8 {
						return fmt.Errorf("failed to decode data bytes: %s", "invalid PasswordPolicyResponse enum value")
					}
					val := int8(bs[0])
					child.Description = "Error"
					child.Value = val
				}
			}
		}
	}
	return nil
}
*/
