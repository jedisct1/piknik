// Copryright (C) 2019 Yawning Angel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package hardware provides the hardware accelerated ChaCha20 implementations.
package hardware

import "gitlab.com/yawning/chacha20.git/internal/api"

var hardwareImpls []api.Implementation

// Register appends the implementation(s) to the provided slice, and returns the
// new slice.
func Register(impls []api.Implementation) []api.Implementation {
	return append(impls, hardwareImpls...)
}
