package crowdstrikelogs

import (
	"fmt"
	"testing"
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes/logtesting"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

func TestUserIdentityParser(t *testing.T) {
	const timestamp = 1590364238848
	ts := tcodec.UnixMilliseconds(timestamp)
	parser := TypeUserIdentity
	cases := [][]string{
		// MAC platform event
		{
			fmt.Sprintf(`{
				"event_simpleName": "UserIdentity",
				"name": "UserIdentity",
				"AuthenticationId": 996,
				"UserPrincipal": "Test-User-Principal",
				"UserSid": "5eb49a6fae459e19",
				"UID": 7893,
				"id": "5eb49a6f-9e19-11ea-b387-06c8bf30f3b9",
				"aid": "5be0664506294ed0427671ed0563f1f8",
				"timestamp": %d,
				"event_platform": "Mac",
				"aip": "10.0.0.1"
			}`,
				timestamp),
			fmt.Sprintf(`{
				"event_simpleName": "UserIdentity",
				"name": "UserIdentity",
				"AuthenticationId": 996,
				"UserPrincipal": "Test-User-Principal",
				"UserSid": "5eb49a6fae459e19",
				"UID": 7893,
				"id": "5eb49a6f-9e19-11ea-b387-06c8bf30f3b9",
				"aid": "5be0664506294ed0427671ed0563f1f8",
				"timestamp": 1590364238848,
				"event_platform": "Mac",
				"aip": "10.0.0.1",
				"p_any_ip_addresses": ["10.0.0.1"],
				"p_any_trace_ids": ["5be0664506294ed0427671ed0563f1f8", "5eb49a6fae459e19"],
				"p_event_time": "%s",
				"p_log_type": "%s"
			}`,
				ts.UTC().Format(time.RFC3339Nano),
				parser,
			),
		},
		// Windows platform event
		{
			fmt.Sprintf(`{
				"event_simpleName": "UserIdentity",
				"name": "UserIdentity",
				"AuthenticationId": 996,
				"UserPrincipal": "Test-User-Principal",
				"UserSid": "5eb49a6fae459e19",
				"id": "5eb49a6f-9e19-11ea-b387-06c8bf30f3b9",
				"aid": "5be0664506294ed0427671ed0563f1f8",
				"timestamp": %d,
				"event_platform": "Win",
				"aip": "10.0.0.1",
				"UserName": "TestUser",
				"UserCanonical": "TestUserCanonical",
				"LogonId": 123456789,
				"LogonDomain": "Test/Domain",
				"AuthenticationPackage": "Package1",
				"LogonType": 2,
				"LogonTime": 1590364238,
				"LogonServer": "TestLogonServer",
				"UserFlags": 32768,
				"PasswordLastSet": 1590064127,
				"RemoteAccount": 0,
				"UserIsAdmin": 0,
				"SessionId": 1929203,
				"UserLogonFlags": 4
				}`,
				timestamp),
			fmt.Sprintf(`{
				"event_simpleName": "UserIdentity",
				"name": "UserIdentity",
				"AuthenticationId": 996,
				"UserPrincipal": "Test-User-Principal",
				"UserSid": "5eb49a6fae459e19",
				"UserName": "TestUser",
				"UserCanonical": "TestUserCanonical",
				"LogonId": 123456789,
				"LogonDomain": "Test/Domain",
				"AuthenticationPackage": "Package1",
				"LogonType": 2,
				"LogonTime": 1590364238,
				"LogonServer": "TestLogonServer",
				"UserFlags": 32768,
				"PasswordLastSet": 1590064127,
				"RemoteAccount": 0,
				"UserIsAdmin": 0,
				"SessionId": 1929203,
				"UserLogonFlags": 4,
				"id": "5eb49a6f-9e19-11ea-b387-06c8bf30f3b9",
				"aid": "5be0664506294ed0427671ed0563f1f8",
				"timestamp": %d,
				"event_platform": "Win",
				"aip": "10.0.0.1",
				"p_any_ip_addresses": ["10.0.0.1"],
				"p_any_trace_ids": ["5be0664506294ed0427671ed0563f1f8", "5eb49a6fae459e19"],
				"p_event_time": "%s",
				"p_log_type": "%s"
				}`,
				timestamp,
				ts.UTC().Format(time.RFC3339Nano),
				parser),
		},
	}

	for _, testcase := range cases {
		logtesting.TestRegisteredParser(t, LogTypes(), parser.String(), testcase[0], testcase[1])
	}
}

func TestGroupIdentityParser(t *testing.T) {
	const timestamp = 1590364238848
	ts := tcodec.UnixMilliseconds(timestamp)
	parser := TypeGroupIdentity
	input := fmt.Sprintf(`{
				"event_simpleName": "GroupIdentity",
				"name": "GroupIdentity",
				"AuthenticationId": 996,
				"UserPrincipal": "Test-User-Principal",
				"UserSid": "5eb49a6fae459e19",
				"AuthenticationUuid": "abcdefghi",
				"AuthenticationUuidAsString": "abcdefghi",
				"GID": 7893,
				"id": "5eb49a6f-9e19-11ea-b387-06c8bf30f3b9",
				"aid": "5be0664506294ed0427671ed0563f1f8",
				"timestamp": %d,
				"event_platform": "Mac",
				"aip": "10.0.0.1"
				}`,
		timestamp)

	expect := fmt.Sprintf(`{
				"event_simpleName": "GroupIdentity",
				"name": "GroupIdentity",
				"AuthenticationUuid": "abcdefghi",
				"AuthenticationUuidAsString": "abcdefghi",
				"AuthenticationId": 996,
				"UserPrincipal": "Test-User-Principal",
				"UserSid": "5eb49a6fae459e19",
				"GID": 7893,
				"id": "5eb49a6f-9e19-11ea-b387-06c8bf30f3b9",
				"aid": "5be0664506294ed0427671ed0563f1f8",
				"timestamp": %d,
				"event_platform": "Mac",
				"aip": "10.0.0.1",
				"p_any_ip_addresses": ["10.0.0.1"],
				"p_any_trace_ids": ["5be0664506294ed0427671ed0563f1f8", "5eb49a6fae459e19"],
				"p_event_time": "%s",
				"p_log_type": "%s"
				}`,
		timestamp,
		ts.UTC().Format(time.RFC3339Nano),
		parser)

	logtesting.TestRegisteredParser(t, LogTypes(), parser.String(), input, expect)
}
