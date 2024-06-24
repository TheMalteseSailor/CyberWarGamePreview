# Cyber War: Choose your contract and become an unstoppable hacking force.

$${\color{red}DEVELOPER \space BUILD}$$

### License
GNU GPL. You can use for free, but please don't steal or make money from without contacting me first.

### Notes to players
- This game preview is not fully functional.
- The current build lacks the contracting mechanics as well as monetary values associated with actions and tools.
- The Administrator (antagonist) has not been implemented in this build, but will be in upcoming previews. 

### Game Description
Cyber War is a terminal based table-top-like RTS where you play as the teamlead for a Cyber Private Military Contractor (C-PMC). Remember, just because you're doing government business doesn't mean your sloppy mistakes wont get you killed if it pisses off the wrong people in power.

Hack your way through various networks and accomplish missions for large sums of money. Hone your skills and lead your team accross dynamically generated target networks to achieve the mission specified in the contract to earn mountains of fiat green rectangles. 

Develop novel exploits and backdoors to move around your target networks. But, be careful not to get sloppy. Not all network admins are made equal and some of them will eat your lunch if you get to cocky. 

### Objectives
Select your contract and mission. Hack the network, but ensure that you don't get cought by the administrator or burn your exploits and tools. 

### Capability Types
- __Exploits__
  - __RCE__ - Remote Code Execution - Gain access to a system via exploit
  - __LPE__ - Local Privilege Escilation - Elevate permissions to a higher level
  - __Lateral__ - This is coverals various exploit types to include credential usage, internal proprietary software, etc.
- __Tools__
  - __RAT__ - Remote Access Tool - A non-persistant tool used to direct access to a system
  - __Beaconinig implant__ - A persistant tool that once installed will allow for reconnecting to the target no matter where it is in the network. If you lose all of your redirectors all of your beaconing implants will automatically uninstall
  - __Triggerable implant__ - A persistant tool that once installed will allow for reconnecting to the target as long as you have direct access to the system and the listening port on the targeted system is listening and accessable. 
  - __Ransomware__ - [NOT IMPLEMENTED]
  - __virus__ - [NOT IMPLEMENTED]
  - __System monitsor__ - [NOT IMPLEMENTED]

### Permission levels
When you develop a capability, when making a selection from the decision table the permission level of the tool and access level provided by an exploit is chosen. If you're in a network that uses an EDR heavily and/or thr Administrator is sharp you'll want to pay the additional costs for the more privilaged capabilitie.
  - __User__ - Basic access, very likely to get cought by an EDR and/or Admin.  
  - __Limited service__ - Essentially, the same access level as User, but more blended and has a slightly lower chance of getting cought by EDR and/or Admin. It may also potentially get past a host based firewall.
  - __System__ - This is the the NT\SYSTEM on Windows, root on Linux, etc.. This access level comes with EDR, firewall, and Admin bypass potential and improved roll potential. 
  - __Kernel__ - You are in the core of the system. Detection is very unlikly. Success roles are very likely and detection likelihood is low however, failures have a far worse outcome. 

### System Access
- __Exploit__ - This is the most basic access level of a system. You can use this instance to upload a follow-on stage to the system. You cannot scan or exploit past a system via this level of access. Utilize the 'implant'/'install' command to upload an immplant type capability to the system.
- __Implant__ - This level of access includes RATs, Beaconing implants, and triggerable implants. You can use this level of access to scan and exploit past that specific system. It can also be used to upload additional capes to the target.

### Commands
- __scan__: scans for targets
	- ex. scan target
	- ex. scan segment from target #
- __exploit|pop__
	- rce ex. pop target 1 with <cape_sn> from rdr
	- rce ex. pop target 2 with <cape_sn> from target 1
    - lpe ex. pop target 1 with <cape_sn>
      - Tools do not inherit the the exploits elevated permissions. 
      - You must develop a tool that can function at that permission level.
- __implant|install__
	- ex. implant target 1 with <cape_sn>
- __develop|dev__
	- ex. dev windows rce 443 tcp
	- ex. dev windows rat
	- ex. dev linux beaconing
	- ex. dev router triggerable 12345 udp
- __get__
	- ex. get rdr
- __show__
	- ex. show targets
	- ex. show team
- __connect__
    - ex. connect to target 1 with <cape_sn>
- __disconnect__
    - ex. disconnect <instance_id> from target #
- __remove__
  - ex. remove <cape_sn> from target #
    
### Game Mechanics
__NOTE__: Whenever a decision table is presented, you are rolling a series of dice to determine your success or failure.
- __1st__: You need to ascertain if your team has any redirectors by using the 'show team' command to display your team information.
- __2nd__: You then need to scan the target network by using the 'scan target' command. If successful you will be presented with the devices that are exposed to the internet (aka edge nodes).
- __3rd__: You will either utilize an exploit in your inventory or develop an appropriate one based on the desired target's platform type, targeted service port, and protocol. s
- __4th a__: If you don't have an appropriate RAT or other implant avilable you can develop that now for future deployment for elevated starget access.
- __4th b__: Utilizing an appropriate exploit, use the 'exploit' command to exploit the desired target. An example of this command is "exploit target 1 with [cape_sn] from redirector"\
__NOTE__: Once you gain initial access to a target system, you will obtain additional system data presented in the 'show targets' command. This is essentially is considered system survey data.
- __5th__: Now that you have an exploit session on the system, you need to elevate your access to either a RAT or implant session. This can be done with the 'implant' or 'install' command. An example of this is "implant target 1 with [cape_sn]"
- __6th__: now you have sufficient access to progress past this specific device. to scan past this device utilize the 'scan' command to scan any network segment that specific system is connected to. An example of this is "scan segment from target 1"
- __7th__: Start the loop again at number 3.


### Term Definitions
- __cape_sn__ - capability serial number assigned at development time
- __instance_id__ - a unique id assigned to a specific tool instance assocaited with a player/npc connection to a target. This is issued at tool deployment time or player/npc connection time.
- __rdr__ - shorthand for redirecter or a pivot system outside of the target network
- 


### Character Traits Definition
- __P__ - programming - The proficiency of programminng in C, C++, and other compiled\semi-compiled languages
- __S__ - scripting - The proficiency of that hacker to write efficient and effective scripts for automating tasks
- __NE__ - network exploitation - The proficiency of a specific hacker to hack through a network utilizing various tools. This value is the posession of the knowlage to perform that action.
- __ED__ - Exploit Developement - This is proficiency to find bugs and convert them to exploits.
- __Not shown__ - personality bonus - [Not Implemented] - can be used as a wild card value to help obtain a successful dice role associated with a decision table. 

### Game Flow Examples
<details>
<summary> Basic target network scan and target listing. </summary>

```
[TheMalteseSailor] > show team

\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
        \\\\\\\ TEAM DETAILS \\\\\\\
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
-- Team Details:
        \___ Redirector Count: 1
        \___ Team Members:
        -- Name: TheMalteseSailor
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 1, S: 3, NE: 1, ED: 2, PER: 1
            \___ Targets:
            \___ Capabilities:
                 \___ Tools: {'type': 'tool', 'name': '553217', 'sub_type': 'system_monitor', 'port': None, 'platform_type': 'firewall', 'burned': False, 'permissions': 'system'}
                 \___ Exploits: {'type': 'exploit', 'name': '135016', 'sub_type': 'lpe', 'port': None, 'platform_type': 'linux', 'burned': False, 'permissions': 'kernel'}
        -- Name: test1
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 3, S: 4, NE: 1, ED: 1, PER: 4
            \___ Targets:
            \___ Capabilities:
                 \___ Tools: {'type': 'tool', 'name': '568861', 'sub_type': 'system_monitor', 'port': None, 'platform_type': 'windows', 'burned': True, 'permissions': 'kernel'}
        -- Name: test5
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 4, S: 4, NE: 2, ED: 4, PER: 1
            \___ Targets:
            \___ Capabilities:
                 \___ Exploits: {'type': 'exploit', 'name': '244752', 'sub_type': 'lateral', 'port': None, 'platform_type': 'firewall', 'burned': False, 'permissions': 'limited service'}
        -- Name: test2
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 4, S: 1, NE: 4, ED: 3, PER: 3
            \___ Targets:
            \___ Capabilities:
                 \___ Exploits: {'type': 'exploit', 'name': '357310', 'sub_type': 'rce', 'port': (443, 'TCP'), 'platform_type': 'linux', 'burned': False, 'permissions': 'limited service'}
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
        ///////      END     ///////
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

[TheMalteseSailor] > scan target
[DEBUG] cmd:

[+] Option 1
 -- Definition:
     \__ Use aggressive nmap scan against all ports of the target's externally facing systems.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 5+ of D20
 -- Bonus Chance: (0, 0)
 -- Failure state: ('failure_state', False)

[+] Option 2
 -- Definition:
     \__ A slower, but still broad scan of the target's externally facing systems.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 2
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 3
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 11)
 -- Failure state: ('failure_state', False)
[TheMalteseSailor] [cancel|#] choice? 1
[DEBUG] decison: 1
[Narrator] Dice roll Succeded.
    \__ Needed: 5 on a D20
    \__ Your Roll: 19

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[TheMalteseSailor] > show targets
---------------------------------------------------------------------
 Target: target 1, Access: False, OS: linux
    Visible Ports: [(69, 'TCP'), (25, 'TCP')]
    Edge Node: True, Pri Net Seg: 1
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 2, Access: False, OS: firewall
    Visible Ports: [(22, 'TCP')]
    Edge Node: True, Pri Net Seg: 1
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 3, Access: False, OS: firewall
    Visible Ports: [(443, 'TCP')]
    Edge Node: True, Pri Net Seg: 1
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 4, Access: False, OS: router
    Visible Ports: [(22, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
[TheMalteseSailor] >
```
</details>


<details>
<summary>Basic Game mechanics and game play.</summary>

```

________/\\\\\\\\\________________/\\\_____________________________________
 _____/\\\////////________________\/\\\_____________________________________
  ___/\\\/______________/\\\__/\\\_\/\\\_____________________________________
   __/\\\_______________\//\\\/\\\__\/\\\____________/\\\\\\\\___/\\/\\\\\\\__
    _\/\\\________________\//\\\\\___\/\\\\\\\\\____/\\\/////\\\_\/\\\/////\\\_
     _\//\\\________________\//\\\____\/\\\////\\\__/\\\\\\\\\\\__\/\\\___\///__
      __\///\\\___________/\\_/\\\_____\/\\\__\/\\\_\//\\///////___\/\\\_________
       ____\////\\\\\\\\\_\//\\\\/______\/\\\\\\\\\___\//\\\\\\\\\\_\/\\\_________
        _______\/////////___\////________\/////////_____\//////////__\///__________
 ________________________________/\\\______________/\\\______________________________
  _______________________________\/\\\_____________\/\\\______________________________
   _______________________________\/\\\_____________\/\\\______________________________
    _______________________________\//\\\____/\\\____/\\\___/\\\\\\\\\_____/\\/\\\\\\\__
     ________________________________\//\\\__/\\\\\__/\\\___\////////\\\___\/\\\/////\\\_
      _________________________________\//\\\/\\\/\\\/\\\______/\\\\\\\\\\__\/\\\___\///__
       __________________________________\//\\\\\\//\\\\\______/\\\/////\\\__\/\\\_________
        ___________________________________\//\\\__\//\\\______\//\\\\\\\\/\\_\/\\\_________
         ____________________________________\///____\///________\////////\//__\///__________


        A game to LARP as a Digital PMC..
                By TheMalteseSailor


        Build your team! Accept your mission!

[-] Choose 3 hackers to be on your team.
==============================================
=============== TEAM SELECTION ===============
-----------------------------------------------------------------------------------
Option Number: 1
Name: test7
    \__Skill Levels:
        \__Programming: 3
        \__Scripting: 4
        \__Network Exploitation: 2
        \__Exploit Development: 1
        \__Personnality Bonus: 1
    \___ Capabilities:
         \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                   \___  tool  | system_monitor | 230227  | None             | firewall | False  | user
-----------------------------------------------------------------------------------
Option Number: 2
Name: test5
    \__Skill Levels:
        \__Programming: 1
        \__Scripting: 4
        \__Network Exploitation: 1
        \__Exploit Development: 3
        \__Personnality Bonus: 4
    \___ Capabilities:
         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                  \___ exploit | rce            | 004672  | (445, 'TCP')     | windows  | False  | system
                  \___ exploit | lateral        | 718036  | None             | windows  | False  | system
-----------------------------------------------------------------------------------
Option Number: 3
Name: test4
    \__Skill Levels:
        \__Programming: 4
        \__Scripting: 3
        \__Network Exploitation: 1
        \__Exploit Development: 2
        \__Personnality Bonus: 1
    \___ Capabilities:
         \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                   \___  tool  | trojan         | 682283  | None             | router   | False  | kernel
                   \___  tool  | virus          | 358203  | None             | router   | False  | limited service
-----------------------------------------------------------------------------------
Option Number: 4
Name: test9
    \__Skill Levels:
        \__Programming: 4
        \__Scripting: 4
        \__Network Exploitation: 2
        \__Exploit Development: 4
        \__Personnality Bonus: 3
    \___ Capabilities:
         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                  \___ exploit | lpe            | 117380  | None             | linux    | True   | user
                  \___ exploit | lateral        | 816752  | None             | router   | False  | limited service
-----------------------------------------------------------------------------------
Option Number: 5
Name: test1
    \__Skill Levels:
        \__Programming: 2
        \__Scripting: 3
        \__Network Exploitation: 4
        \__Exploit Development: 2
        \__Personnality Bonus: 4
    \___ Capabilities:
         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                  \___ exploit | lpe            | 108022  | None             | router   | False  | system
                  \___ exploit | rce            | 218866  | (443, 'TCP')     | linux    | False  | system
-----------------------------------------------------------------------------------
Option Number: 6
Name: test8
    \__Skill Levels:
        \__Programming: 1
        \__Scripting: 3
        \__Network Exploitation: 3
        \__Exploit Development: 4
        \__Personnality Bonus: 4
    \___ Capabilities:
         \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                   \___  tool  | keylogger      | 734468  | None             | router   | False  | limited service
         \____________________________________________________________________________________________________
                                                                                                              \
         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                  \___ exploit | lpe            | 707182  | None             | router   | False  | kernel
==============================================
[?] Make your NPC selections by providing the NPC's 'Option Number'.
[?] NPC1 selection? 1
[?] NPC2 selection? 2
[?] NPC3 selection? 3
[ ] You've chosen to make you team with: test7, test5, and test4.
[?] What size network? [Small|Medium|Large|Huge]small

[TheMalteseSailor] > show team

\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
        \\\\\\\ TEAM DETAILS \\\\\\\
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
-- Team Details:
        \___ Redirector Count: 0
        \___ Team Members:
        -- Name: TheMalteseSailor
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 3, S: 1, NE: 1, ED: 3, PER: 3
            \___ Targets:
            \___ Capabilities:
                 \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                           \___  tool  | trojan         | 524021  | None             | router   | False  | kernel
                           \___  tool  | keylogger      | 351355  | None             | windows  | False  | user
        -- Name: test7
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 3, S: 4, NE: 2, ED: 1, PER: 1
            \___ Targets:
            \___ Capabilities:
                 \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                           \___  tool  | system_monitor | 230227  | None             | firewall | False  | user
        -- Name: test5
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 1, S: 4, NE: 1, ED: 3, PER: 4
            \___ Targets:
            \___ Capabilities:
                 \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                          \___ exploit | rce            | 004672  | (445, 'TCP')     | windows  | False  | system
                          \___ exploit | lateral        | 718036  | None             | windows  | False  | system
        -- Name: test4
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 4, S: 3, NE: 1, ED: 2, PER: 1
            \___ Targets:
            \___ Capabilities:
                 \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                           \___  tool  | trojan         | 682283  | None             | router   | False  | kernel
                           \___  tool  | virus          | 358203  | None             | router   | False  | limited service
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
        ///////      END     ///////
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

[TheMalteseSailor] > get rdr
[DEBUG] cmd: ['rdr']

[+] Option 1
 -- Definition:
     \__ Use a wellknown VPS service with gift card.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 2+ of D20
 -- Bonus Chance: (0, 0)
 -- Failure state: ('failure_state', False)

[+] Option 2
 -- Definition:
     \__ Use a less known, but kinda sketchy VPS provider. Has chance for more than one redirector acquired.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 2
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 0+ of D0
 -- Bonus Chance: (10, 5)
 -- Failure state: ('failure_state', False)

[+] Option 3
 -- Definition:
     \__ Use tumbled bitcoin to purchase reputable normie VPS.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 2
     \__ programming: 0
     \__ scripting: 2
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (15, 11)
 -- Failure state: ('failure_state', False)

[+] Option 4
 -- Definition:
     \__ Purchase verified anonymous VPS with Monero. Has chance to aquire more than one redirector.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 3
     \__ programming: 0
     \__ scripting: 2
 -- Failure Cost: 2
 -- Chance: Requires 10+ of D20
 -- Bonus Chance: (10, 9)
 -- Failure state: ('failure_state', False)
[TheMalteseSailor] [cancel|#] choice? 1
[DEBUG] decison: 1
[Narrator] Dice roll Succeded.
    \__ Needed: 2 on a D20
    \__ Your Roll: 3

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[TheMalteseSailor] > scan target
[DEBUG] cmd:

[+] Option 1
 -- Definition:
     \__ Use aggressive nmap scan against all ports of the target's externally facing systems.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 5+ of D20
 -- Bonus Chance: (0, 0)
 -- Failure state: ('failure_state', False)

[+] Option 2
 -- Definition:
     \__ A slower, but still broad scan of the target's externally facing systems.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 2
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 3
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 8)
 -- Failure state: ('failure_state', False)
[TheMalteseSailor] [cancel|#] choice? 1
[DEBUG] decison: 1
[Narrator] Failed dice roll for initial success.
    \__ Needed: 5 on a D20
    \__ Your Roll: 2
[Narrator] No valid option or tasking commmand supplied.
[DEBUG] Calling background task worker thread from failure status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[TheMalteseSailor] > scan target
[DEBUG] cmd:

[+] Option 1
 -- Definition:
     \__ Use aggressive nmap scan against all ports of the target's externally facing systems.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 5+ of D20
 -- Bonus Chance: (0, 0)
 -- Failure state: ('failure_state', False)

[+] Option 2
 -- Definition:
     \__ A slower, but still broad scan of the target's externally facing systems.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 2
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 3
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 2)
 -- Failure state: ('failure_state', False)
[TheMalteseSailor] [cancel|#] choice? 1
[DEBUG] decison: 1
[Narrator] Failed dice roll for initial success.
    \__ Needed: 5 on a D20
    \__ Your Roll: 3
[Narrator] No valid option or tasking commmand supplied.
[DEBUG] Calling background task worker thread from failure status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[TheMalteseSailor] > scan target
[DEBUG] cmd:

... decision table snipped ...

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[TheMalteseSailor] > show targets
---------------------------------------------------------------------
 Target: target 1, Access: False, OS: linux
    Visible Ports: [(22, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 2, Access: False, OS: linux
    Visible Ports: [(123, 'TCP'), (110, 'TCP'), (25, 'TCP'), (443, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 3, Access: False, OS: router
    Visible Ports: [(443, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 4, Access: False, OS: linux
    Visible Ports: [(21, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 5, Access: False, OS: linux
    Visible Ports: [(123, 'TCP'), (25, 'TCP'), (22, 'TCP')]
    Edge Node: True, Pri Net Seg: 3
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
[TheMalteseSailor] > dev linux rce 22 tcp
[DEBUG] cmd: ['linux', 'rce', '22', 'tcp']
[ ] invalid protocol provided.

[+] Option 1
 -- Definition:
     \__ Lower skilled effort with longer time requirements
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 5+ of D20
 -- Bonus Chance: (0, 0)
 -- Failure state: ('failure_state', False)

[+] Option 2
 -- Definition:
     \__ Intermediate skilled effort with shorter, but still longer time requirements
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 19)
 -- Failure state: ('failure_state', False)

[+] Option 3
 -- Definition:
     \__ Advanced skilled effort with acceptable time requirements.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 12)
 -- Failure state: ('failure_state', False)

[+] Option 4
 -- Definition:
     \__ Expert skilled effort with short time requirements.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 11)
 -- Failure state: ('failure_state', False)
[TheMalteseSailor] [cancel|#] choice? 1
[DEBUG] decison: 1
[Narrator] Dice roll Succeded.
    \__ Needed: 5 on a D20
    \__ Your Roll: 9

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[DEBUG] added {'type': 'exploit', 'name': '466133', 'sub_type': 'rce', 'port': ('22', 'tcp'), 'platform_type': 'linux', 'burned': False, 'permissions': 'user'}

{'type': 'exploit', 'name': '466133', 'sub_type': 'rce', 'port': ('22', 'tcp'), 'platform_type': 'linux', 'burned': False, 'permissions': 'user'}

[TheMalteseSailor] > pop target 1 with 466133 from rdr
[DEBUG] cmd: ['target', '1', 'with', '466133', 'from', 'rdr']
[DEBUG] cape_sn in cape_sn_tracker.
[DEBUG] cape_sn in cape_sn_tracker.
[DEBUG] Target is visible and ports are visible.
[DEBUG] targeted port is open.

[+] Option 1
 -- Definition:
     \__ Use aggressive nmap scan against all ports of the target's externally facing systems.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 5+ of D20
 -- Bonus Chance: (0, 0)
 -- Failure state: ('failure_state', False)
[TheMalteseSailor] [cancel|#] choice? 1
[DEBUG] decison: 1
[Narrator] Dice roll Succeded.
    \__ Needed: 5 on a D20
    \__ Your Roll: 10

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[TheMalteseSailor] > show targets
---------------------------------------------------------------------
 Target: target 1, Access: True, OS: linux
    Visible Ports: [(22, 'TCP')]
    System details: EDR:False, FW:False, Function:
    Edge Node: True, Dual Homed: True, Pri Net Seg: 2, Alt Net Seg: 3
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
       rce         | 466133  | False  | user        | True    | ['880555']  |
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 2, Access: False, OS: linux
    Visible Ports: [(123, 'TCP'), (110, 'TCP'), (25, 'TCP'), (443, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 3, Access: False, OS: router
    Visible Ports: [(443, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 4, Access: False, OS: linux
    Visible Ports: [(21, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 5, Access: False, OS: linux
    Visible Ports: [(123, 'TCP'), (25, 'TCP'), (22, 'TCP')]
    Edge Node: True, Pri Net Seg: 3
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
[TheMalteseSailor] > dev linux rat
[DEBUG] cmd: ['linux', 'rat']

[+] Option 1
 -- Definition:
     \__ Lower skilled effort with longer time requirements
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 5+ of D20
 -- Bonus Chance: (0, 0)
 -- Failure state: ('failure_state', False)

[+] Option 2
 -- Definition:
     \__ Intermediate skilled effort with shorter, but still longer time requirements
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 13)
 -- Failure state: ('failure_state', False)

[+] Option 3
 -- Definition:
     \__ Advanced skilled effort with acceptable time requirements.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 17)
 -- Failure state: ('failure_state', False)

[+] Option 4
 -- Definition:
     \__ Expert skilled effort with short time requirements.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 17)
 -- Failure state: ('failure_state', False)
[TheMalteseSailor] [cancel|#] choice? 1
[DEBUG] decison: 1
[Narrator] Dice roll Succeded.
    \__ Needed: 5 on a D20
    \__ Your Roll: 9

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[DEBUG] added {'type': 'tool', 'name': '072141', 'sub_type': 'rat', 'port': None, 'platform_type': 'linux', 'burned': False, 'permissions': 'user'}

{'type': 'tool', 'name': '072141', 'sub_type': 'rat', 'port': None, 'platform_type': 'linux', 'burned': False, 'permissions': 'user'}

[TheMalteseSailor] > implant target 1 with 072141

[+] Option 1
 -- Definition:
     \__ Use aggressive nmap scan against all ports of the target's externally facing systems.
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 5+ of D20
 -- Bonus Chance: (0, 0)
 -- Failure state: ('failure_state', False)
[TheMalteseSailor] [cancel|#] choice? 1
[DEBUG] decison: 1
[Narrator] Dice roll Succeded.
    \__ Needed: 5 on a D20
    \__ Your Roll: 8

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[TheMalteseSailor] > show targets
---------------------------------------------------------------------
 Target: target 1, Access: True, OS: linux
    Visible Ports: [(22, 'TCP')]
    System details: EDR:False, FW:False, Function:
    Edge Node: True, Dual Homed: True, Pri Net Seg: 2, Alt Net Seg: 3
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
       rce         | 466133  | False  | user        | False   | ['880555']  |
       rat         | 072141  | False  | user        | True    | ['880555']  |
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 2, Access: False, OS: linux
    Visible Ports: [(123, 'TCP'), (110, 'TCP'), (25, 'TCP'), (443, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 3, Access: False, OS: router
    Visible Ports: [(443, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 4, Access: False, OS: linux
    Visible Ports: [(21, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
---------------------------------------------------------------------
 Target: target 5, Access: False, OS: linux
    Visible Ports: [(123, 'TCP'), (25, 'TCP'), (22, 'TCP')]
    Edge Node: True, Pri Net Seg: 3
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
[TheMalteseSailor] >
```
</pre>
</details>