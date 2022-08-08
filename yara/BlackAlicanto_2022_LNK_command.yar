/*
Copyright 2021 PwC UK
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

rule BlackAlicanto_2022_LNK_command : Black_Alicanto
{
	meta:
		description = "Detects malicious LNK files used by Black Alicanto in 2022 based on the command it executes when launched by the victim."
		TLP = "WHITE"
		author = "PwC Cyber Threat Operations :: cyberoverdrive"
		copyright = "Copyright PwC UK 2022 (C)"
		license = "Apache License, Version 2.0"
		created_date = "2022-08-05"
		modified_date = "2022-08-05"
		revision = "0"
		hash = "f7170b70a89f4b5d196e3a09c1d6135d36320548f66cdc2c55bf725b0f8d4ab8"
		hash = "1e154b2976cc00d457c0dc2b83ebe81911294c8276691617085c03a3304fd87f"
		hash = "81554ae36513b4a637d72db864f31e39ef3ae35ad402fb170f5e5fddee2d4589"
		hash = "6047a46276a3231b0d3d6626cf4a864484648aced201b998ddc7f9fb98d46ddb"

	strings:
		// /q /c type %systemroot%\system32\msh*.exe>%public%\msh&ren %public%\* *ta.exe
		$cmd = {2f 00 71 00 20 00 2f 00 63 00 20 00 74 00 79 00 70 00 65 00 20 00 25 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 68 00 2a 00 2e 00 65 00 78 00 65 00 3e 00 25 00 70 00 75 00 62 00 6c 00 69 00 63 00 25 00 5c 00 6d 00 73 00 68 00 26 00 72 00 65 00 6e 00 20 00 25 00 70 00 75 00 62 00 6c 00 69 00 63 00 25 00 5c 00 2a 00 20 00 2a 00 74 00 61 00 2e 00 65 00 78 00 65}

	condition:
		$cmd
}