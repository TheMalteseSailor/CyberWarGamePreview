# Cyber War: Choose your contract and become an unstoppable hacking force.

$${\color{red}Pre-Alpha}$$

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
1. Select your contract and mission. Hack the network, but ensure that you don't get cought by the administrator or burn your exploits and tools. 

2. This game was designed for folks who are either new to the field or who largely need to understand the mindset of how hackers compromise, move, etc. in a target network.


### Platform / Operating System (OS) Types
- __Windows__ - 
- __Linux__ - 
- __Firewall__ - 
- __Router__ - 
- __Embedded__ - 

 __Note__: The platform types are chosen at random when the game is constructing the target network(s).
 
 __Note__: Each platform / OS type has a range of ports that are associated with that platform. 

 __Note__: There are no architectures tracked or defined. 

### Permission levels
When you develop a capability, when making a selection from the decision table the permission level of the tool and access level provided by an exploit is chosen. If you're in a network that uses an EDR heavily and/or thr Administrator is sharp you'll want to pay the additional costs for the more privilaged capabilitie.  
  - __User__ - Basic access, very likely to get cought by an EDR and/or Admin.  
  - __Limited service__ - Essentially, the same access level as User, but more blended and has a slightly lower chance of getting cought by EDR and/or Admin. It may also potentially get past a host based firewall.
  - __System__ - This is the the NT\SYSTEM on Windows, root on Linux, etc.. This access level comes with EDR, firewall, and Admin bypass potential and improved roll potential. 
  - __Kernel__ - You are in the core of the system. Detection is very unlikly. Success roles are very likely and detection likelihood is low however, failures have a far worse outcome. 
##### Exploit Only
  - __VM_Break_In__ - [NOT IMPLEMENTED]
  - __VM_Break_Out__ - [NOT IMPLEMENTED]

### Capability Types
- __Exploits__
  - __RCE__ - Remote Code Execution - Gain access to a system via exploit
  - __LPE__ - Local Privilege Escilation - Elevate permissions to a higher level
  - __Lateral__ - [NOT IMPLEMENTED] This is coverals various exploit types to include credential usage, internal proprietary software, etc.
- __Tools__
  - __RAT__ - Remote Access Tool - A non-persistant tool used to direct access to a system
  - __Beaconinig implant__ - A persistant tool that once installed will allow for reconnecting to the target no matter where it is in the network. If you lose all of your redirectors all of your beaconing implants will automatically uninstall
  - __Triggerable implant__ - A persistant tool that once installed will allow for reconnecting to the target as long as you have direct access to the system and the listening port on the targeted system is listening and accessable. 
  - __Ransomware__ - [NOT IMPLEMENTED]
  - __virus__ - [NOT IMPLEMENTED]
  - __System monitsor__ - [NOT IMPLEMENTED]

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
    - lateral is not implemented....
- __implant|install|upload__
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
- __attack__
  - [NOT IMPLEMENTED]

#### Command Context / Teammate Tasking
The goal of the game is to lead a hacking team. To lead you must be able to task team members. The game uses a per-task context that is initiated by prepending the teammate's name to the front of the command.

- Teammate name is "__test1__".
    - An example of tasking this teammate is "__test1 pop target 1 with 123456 from rdr__".
    - The game supports teammate nicknaming. In the instance of a "test1" teammate name you can proivide a unique nickname.
      - An example of this is "__1 pop target 1 with 123456 from rdr__", as long as "1" is unique.
      - Providing "test" would fail if another teammate has "test" as a substring of their name.
    - This will ultimately allow for the teammates with names like f4tS7aCk5 (FatStacks) to be addressed as either "fat", "stacks", etc.

    
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


### Execute The Game

__NOTE__: python 3.10
```
cd CyberWarGamePreview
python CyberWarGame.py
```


### Game Flow Examples
<details>
<summary> Basic target network scan and target listing. </summary>

```
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
Name: test5
    \__Skill Levels:
        \__Programming: 3
        \__Scripting: 4
        \__Network Exploitation: 1
        \__Exploit Development: 2
        \__Personnality Bonus: 3
    \___ Capabilities:
         \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                   \___  tool  | triggerable    | 838227  | ('36057', 'TCP') | router   | False  | system
         \____________________________________________________________________________________________________
                                                                                                              \
         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                  \___ exploit | rce            | 122288  | (123, 'TCP')     | linux    | False  | user
-----------------------------------------------------------------------------------
Option Number: 2
Name: test7
    \__Skill Levels:
        \__Programming: 1
        \__Scripting: 2
        \__Network Exploitation: 4
        \__Exploit Development: 1
        \__Personnality Bonus: 1
    \___ Capabilities:
         \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                   \___  tool  | triggerable    | 775351  | ('54761', 'TCP') | linux    | False  | user
         \____________________________________________________________________________________________________
                                                                                                              \
         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                  \___ exploit | lpe            | 608205  | None             | firewall | False  | system
-----------------------------------------------------------------------------------
Option Number: 3
Name: test2
    \__Skill Levels:
        \__Programming: 3
        \__Scripting: 2
        \__Network Exploitation: 1
        \__Exploit Development: 3
        \__Personnality Bonus: 2
    \___ Capabilities:
         \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                   \___  tool  | keylogger      | 378812  | None             | router   | True   | system
         \____________________________________________________________________________________________________
                                                                                                              \
         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                  \___ exploit | lateral        | 534075  | None             | linux    | True   | user
-----------------------------------------------------------------------------------
Option Number: 4
Name: test3
    \__Skill Levels:
        \__Programming: 2
        \__Scripting: 3
        \__Network Exploitation: 3
        \__Exploit Development: 2
        \__Personnality Bonus: 1
    \___ Capabilities:
         \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                   \___  tool  | virus          | 456604  | None             | windows  | False  | kernel
         \____________________________________________________________________________________________________
                                                                                                              \
         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                  \___ exploit | lateral        | 524218  | None             | linux    | False  | kernel
-----------------------------------------------------------------------------------
Option Number: 5
Name: test8
    \__Skill Levels:
        \__Programming: 4
        \__Scripting: 4
        \__Network Exploitation: 4
        \__Exploit Development: 2
        \__Personnality Bonus: 3
    \___ Capabilities:
         \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                   \___  tool  | virus          | 122058  | None             | firewall | False  | limited service
         \____________________________________________________________________________________________________
                                                                                                              \
         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                  \___ exploit | lateral        | 557288  | None             | windows  | False  | limited service
-----------------------------------------------------------------------------------
Option Number: 6
Name: test9
    \__Skill Levels:
        \__Programming: 4
        \__Scripting: 2
        \__Network Exploitation: 3
        \__Exploit Development: 2
        \__Personnality Bonus: 1
    \___ Capabilities:
         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                  \___ exploit | lpe            | 734386  | None             | firewall | True   | user
==============================================
[?] Make your NPC selections by providing the NPC's 'Option Number'.
[?] NPC1 selection? 1
[?] NPC2 selection? 2
[?] NPC3 selection? 3

    [{'type': 'tool', 'name': '838227', 'sub_type': 'triggerable', 'port': ('36057', 'TCP'), 'platform_type': 'router', 'burned': False, 'permissions': 'system'}]
    [{'type': 'exploit', 'name': '122288', 'sub_type': 'rce', 'port': (123, 'TCP'), 'platform_type': 'linux', 'burned': False, 'permissions': 'user'}]
    [{'type': 'tool', 'name': '775351', 'sub_type': 'triggerable', 'port': ('54761', 'TCP'), 'platform_type': 'linux', 'burned': False, 'permissions': 'user'}]
    [{'type': 'exploit', 'name': '608205', 'sub_type': 'lpe', 'port': None, 'platform_type': 'firewall', 'burned': False, 'permissions': 'system'}]
    [{'type': 'tool', 'name': '378812', 'sub_type': 'keylogger', 'port': None, 'platform_type': 'router', 'burned': True, 'permissions': 'system'}]
    [{'type': 'exploit', 'name': '534075', 'sub_type': 'lateral', 'port': None, 'platform_type': 'linux', 'burned': True, 'permissions': 'user'}]

[ ] You've chosen to make you team with: test5, test7, and test2.
[?] What size network? [Small|Medium|Large|Huge]small

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
          \___ P: 2, S: 3, NE: 3, ED: 3, PER: 1
            \___ Targets:
            \___ Capabilities:
                 \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                           \___  tool  | beaconing      | 681288  | None             | router   | False  | system
        -- Name: test5
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 3, S: 4, NE: 1, ED: 2, PER: 3
            \___ Targets:
            \___ Capabilities:
                 \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                           \___  tool  | triggerable    | 838227  | ('36057', 'TCP') | router   | False  | system
                 \____________________________________________________________________________________________________
                                                                                                                      \
                 \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                          \___ exploit | rce            | 122288  | (123, 'TCP')     | linux    | False  | user
        -- Name: test7
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 1, S: 2, NE: 4, ED: 1, PER: 1
            \___ Targets:
            \___ Capabilities:
                 \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                           \___  tool  | triggerable    | 775351  | ('54761', 'TCP') | linux    | False  | user
                 \____________________________________________________________________________________________________
                                                                                                                      \
                 \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                          \___ exploit | lpe            | 608205  | None             | firewall | False  | system
        -- Name: test2
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 3, S: 2, NE: 1, ED: 3, PER: 2
            \___ Targets:
            \___ Capabilities:
                 \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                           \___  tool  | keylogger      | 378812  | None             | router   | True   | system
                 \____________________________________________________________________________________________________
                                                                                                                      \
                 \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                          \___ exploit | lateral        | 534075  | None             | linux    | True   | user
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
 -- Bonus Chance: (10, 10)
 -- Failure state: ('failure_state', False)
[TheMalteseSailor] [cancel|#] choice? 1
[DEBUG] decison: 1
[Narrator] Dice roll Succeded.
    \__ Needed: 5 on a D20
    \__ Your Roll: 13

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[TheMalteseSailor] > show targets
---------------------------------------------------------------------
 Target: target 1, Access: False, OS: router
    Visible Ports: [(443, 'TCP')]
    Edge Node: True, Pri Net Seg: 2
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
---------------------------------------------------------------------
[TheMalteseSailor] > dev router rce 443 tcp
[DEBUG] cmd: ['router', 'rce', '443', 'tcp']
[ ] invalid protocol provided.

[+] Option 1
 -- Definition:
     \__ Lower skilled effort with longer time requirements | (User mode)
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
     \__ Intermediate skilled effort with shorter, but still longer time requirements | (Limited Service)
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 6)
 -- Failure state: ('failure_state', False)

[+] Option 3
 -- Definition:
     \__ Advanced skilled effort with acceptable time requirements. | (System)
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 6)
 -- Failure state: ('failure_state', False)

[+] Option 4
 -- Definition:
     \__ Expert skilled effort with short time requirements. | (Kernel)
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 7)
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
[TheMalteseSailor] > dev router rce 443 tcp
[DEBUG] cmd: ['router', 'rce', '443', 'tcp']
[ ] invalid protocol provided.

[+] Option 1
 -- Definition:
     \__ Lower skilled effort with longer time requirements | (User mode)
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
     \__ Intermediate skilled effort with shorter, but still longer time requirements | (Limited Service)
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 5)
 -- Failure state: ('failure_state', False)

[+] Option 3
 -- Definition:
     \__ Advanced skilled effort with acceptable time requirements. | (System)
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 4)
 -- Failure state: ('failure_state', False)

[+] Option 4
 -- Definition:
     \__ Expert skilled effort with short time requirements. | (Kernel)
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 13)
 -- Failure state: ('failure_state', False)
[TheMalteseSailor] [cancel|#] choice? 1
[DEBUG] decison: 1
[Narrator] Dice roll Succeded.
    \__ Needed: 5 on a D20
    \__ Your Roll: 14

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[DEBUG] added {'type': 'exploit', 'name': '637805', 'sub_type': 'rce', 'port': ('443', 'tcp'), 'platform_type': 'router', 'burned': False, 'permissions': 'user'}

{'type': 'exploit', 'name': '637805', 'sub_type': 'rce', 'port': ('443', 'tcp'), 'platform_type': 'router', 'burned': False, 'permissions': 'user'}

[TheMalteseSailor] > pop target 1 with 637805 from rdr
[DEBUG] cmd: ['target', '1', 'with', '637805', 'from', 'rdr']
[DEBUG] cape_sn in cape_sn_tracker.
[DEBUG] cape_sn in cape_sn_tracker.
[DEBUG] Target is visible and ports are visible.
[DEBUG] targeted port is open.

[+] Option 1
 -- Definition:
     \__
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
    \__ Your Roll: 5

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[TheMalteseSailor] > show targets
---------------------------------------------------------------------
 Target: target 1, Access: True, OS: router
    Visible Ports: [(443, 'TCP')]
    System details: EDR:False, FW:False, Function:
    Edge Node: True, Dual Homed: False, Pri Net Seg: 2, Alt Net Seg: 0
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
       rce         | 637805  | False  | user        | True    | ['285033']  |
---------------------------------------------------------------------
[TheMalteseSailor] > dev router rat
[DEBUG] cmd: ['router', 'rat']

[+] Option 1
 -- Definition:
     \__ Lower skilled effort with longer time requirements | (User mode)
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
     \__ Intermediate skilled effort with shorter, but still longer time requirements | (Limited Service)
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 18)
 -- Failure state: ('failure_state', False)

[+] Option 3
 -- Definition:
     \__ Advanced skilled effort with acceptable time requirements. | (System)
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 15)
 -- Failure state: ('failure_state', False)

[+] Option 4
 -- Definition:
     \__ Expert skilled effort with short time requirements. | (Kernel)
 -- Skill Requirements:
     \__ exploit development: 0
     \__ network exploitation: 1
     \__ programming: 0
     \__ scripting: 1
 -- Failure Cost: 2
 -- Chance: Requires 8+ of D20
 -- Bonus Chance: (10, 3)
 -- Failure state: ('failure_state', False)
[TheMalteseSailor] [cancel|#] choice? 1
[DEBUG] decison: 1
[Narrator] Dice roll Succeded.
    \__ Needed: 5 on a D20
    \__ Your Roll: 13

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[DEBUG] added {'type': 'tool', 'name': '764772', 'sub_type': 'rat', 'port': None, 'platform_type': 'router', 'burned': False, 'permissions': 'user'}

{'type': 'tool', 'name': '764772', 'sub_type': 'rat', 'port': None, 'platform_type': 'router', 'burned': False, 'permissions': 'user'}

[TheMalteseSailor] > implant target 1 with 764772

[+] Option 1
 -- Definition:
     \__
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
    \__ Your Roll: 9

[DEBUG] Calling background task worker thread from success status.
[DEBUG] Inside background task worker thread.
final_decision_struct['time cost']: 2
[ ] 1 second(s) remaining for TheMalteseSailor.
[TheMalteseSailor] > show targets
---------------------------------------------------------------------
 Target: target 1, Access: True, OS: router
    Visible Ports: [(443, 'TCP')]
    System details: EDR:False, FW:False, Function:
    Edge Node: True, Dual Homed: False, Pri Net Seg: 2, Alt Net Seg: 0
    Capes Deployed to target.
       TYPE        | CAPE_SN | BURNED | PERMISSIONS | PRESENT | INSTANCE_ID | SRC_INSTANCE_ID
       rce         | 637805  | False  | user        | False   | ['285033']  |
       rat         | 764772  | False  | user        | True    | ['285033']  |
---------------------------------------------------------------------
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
          \___ P: 2, S: 3, NE: 3, ED: 3, PER: 1
            \___ Targets:
              \___ src: rdr, target: target 1, meth: rat(764772)(user), instance_id: 285033, src_instance_id:
            \___ Capabilities:
                 \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                           \___  tool  | beaconing      | 681288  | None             | router   | False  | system
                           \___  tool  | rat            | 764772  | None             | router   | False  | user
                 \____________________________________________________________________________________________________
                                                                                                                      \
                 \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                          \___ exploit | rce            | 637805  | ('443', 'tcp')   | router   | False  | user
        -- Name: test5
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 3, S: 4, NE: 1, ED: 2, PER: 3
            \___ Targets:
            \___ Capabilities:
                 \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                           \___  tool  | triggerable    | 838227  | ('36057', 'TCP') | router   | False  | system
                 \____________________________________________________________________________________________________
                                                                                                                      \
                 \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                          \___ exploit | rce            | 122288  | (123, 'TCP')     | linux    | False  | user
        -- Name: test7
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 1, S: 2, NE: 4, ED: 1, PER: 1
            \___ Targets:
            \___ Capabilities:
                 \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                           \___  tool  | triggerable    | 775351  | ('54761', 'TCP') | linux    | False  | user
                 \____________________________________________________________________________________________________
                                                                                                                      \
                 \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                          \___ exploit | lpe            | 608205  | None             | firewall | False  | system
        -- Name: test2
          \___ Burned Out: False
          \___ Task Timer: 0m0s
          \___ P: 3, S: 2, NE: 1, ED: 3, PER: 2
            \___ Targets:
            \___ Capabilities:
                 \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS
                           \___  tool  | keylogger      | 378812  | None             | router   | True   | system
                 \____________________________________________________________________________________________________
                                                                                                                      \
                 \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS
                          \___ exploit | lateral        | 534075  | None             | linux    | True   | user
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
        ///////      END     ///////
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

[TheMalteseSailor] >
```
</pre>
</details>
