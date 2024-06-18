from CyberWarArt import *
from sys import exc_info, excepthook, stdout
from time import sleep
from random import randrange
from copy import deepcopy
import PlayerUtils
import TargetUtils
import Decision_logic



def introBanner():
    IntroArtOptions = [introOption1,introOption2,introOption3,introOption4,introOption5,introOption6,introOption7]
    intro_selection = randrange(0,7)
    print(IntroArtOptions[intro_selection])

    print(r'''
        A game to LARP as a Digital PMC..
                By TheMalteseSailor

    ''')         

    typing_text = "Build your team! Accept your mission!"
    print("\t", end='')

    for char in [*typing_text]:
            print(char, end="")
            stdout.flush()
            sleep(.1)
   
    print("\n\n")

def playerSelection():

    #Player = PlayerUtils.Player(name="TheMalteseSailor")
    Player = PlayerUtils.PlayerGenerator(name="TheMalteseSailor")

    name_poses = []
    #name_poses.append(randrange(0,len(PlayerUtils.handle_list)-1))
    while len(name_poses)<7:
        pot_name = randrange(0,len(PlayerUtils.handle_list)-1)
        if (PlayerUtils.handle_list[pot_name] not in name_poses):
            name_poses.append(PlayerUtils.handle_list[pot_name])

    NPCs = []

    NPCs.append(PlayerUtils.PlayerGenerator(name=name_poses[0]))
    NPCs.append(PlayerUtils.PlayerGenerator(name=name_poses[1]))
    NPCs.append(PlayerUtils.PlayerGenerator(name=name_poses[2]))
    NPCs.append(PlayerUtils.PlayerGenerator(name=name_poses[3]))
    NPCs.append(PlayerUtils.PlayerGenerator(name=name_poses[4]))
    NPCs.append(PlayerUtils.PlayerGenerator(name=name_poses[5]))

    print("[-] Choose 3 hackers to be on your team.")
    print("==============================================")
    print("=============== TEAM SELECTION ===============")
    for index, npc in enumerate(NPCs):        
        print("-----------------------------------------------------------------------------------")
        print(f"Option Number: {index+1}")
        print(f"Name: {npc.name} ")
        print("    \__Skill Levels: ")
        print(f"\t\__Programming: {npc.programming}")
        print(f"\t\__Scripting: {npc.scripting}")
        print(f"\t\__Network Exploitation: {npc.network_exploitation}")
        print(f"\t\__Exploit Development: {npc.exploit_development}")
        print(f"\t\__Personnality Bonus: {npc.personality_bonus}")
        print(f"    \___ Capabilities:")
        if len(npc.tools) > 0:
            print("         \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS")
            for tool in npc.tools:
                print("\t           \___  {0:5} | {1:14} | {2:6}  | {3:16} | {4:8} | {5:6} | {6:11}".format(tool["type"],tool["sub_type"],tool["name"],str(tool["port"]),tool["platform_type"],str(tool["burned"]),tool["permissions"]))
        if (len(npc.tools) > 0) and (len(npc.exploits) > 0):
            print("\t \____________________________________________________________________________________________________")
            print("\t                                                                                                      \\")
        if len(npc.exploits) > 0:
            print("         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS")
            for exploit in npc.exploits:
                print("\t          \___ {0:5} | {1:14} | {2:6}  | {3:16} | {4:8} | {5:6} | {6:11}".format(exploit["type"],exploit["sub_type"],exploit["name"],str(exploit["port"]),exploit["platform_type"],str(exploit["burned"]),exploit["permissions"]))



    print("==============================================")

    print("[?] Make your NPC selections by providing the NPC's 'Option Number'.")
    selections = []
    while True:
        try:
            selections.append(int(input("[?] NPC1 selection? "))-1)
            selections.append(int(input("[?] NPC2 selection? "))-1)
            selections.append(int(input("[?] NPC3 selection? "))-1)

            # set gets rid of duplicates
            selections = list(set(selections))
            if len(selections) < 3:
                selections = []
                print("[!] You cannot select the same NPC multiple times.")
                print("[-] Choose again.")
                continue
            for selection in selections:
                if ((selection+1 < 1) or (selection+1 > 6)):
                    print("[Failed] A number supplied does not match a provided option.")
                    raise Exception("")
            break

        except:
            selections = []
            print("[!] Something went wrong with your selection choices. ")
            print("[-] Choose again.")
            continue

    NPC1 = NPCs[selections[0]]
    NPC2 = NPCs[selections[1]]
    NPC3 = NPCs[selections[2]]
    print(f"""
    {NPC1.tools}
    {NPC1.exploits}
    {NPC2.tools}
    {NPC2.exploits}
    {NPC3.tools}
    {NPC3.exploits}
    """)
    print(rf"[ ] You've chosen to make you team with: {NPC1.name}, {NPC2.name}, and {NPC3.name}.")
    Team = PlayerUtils.hackingTeam(Player, NPC1, NPC2, NPC3)
    return Team


# This my need to be merged with ui_interface  
def MainGameLoop():
    HackingTeam = playerSelection()
    # Generate target network
    network_size = ""
    while True:
        network_size = input("[?] What size network? [Small|Medium|Large|Huge]")
        network_size = network_size.lower()

        if (network_size != 'small') and (network_size != 'medium') and (network_size != 'large') and (network_size != 'huge'):
            print("[!] Error: invalid network size selection.")
        else:
            break
     
    TargetNetwork = TargetUtils.TargetNetwork(network_size)
    
    npc_names = [HackingTeam.npc1.name.lower(), HackingTeam.npc2.name.lower(), HackingTeam.npc3.name.lower()]

    game_active = True
    #context = HackingTeam.player
    while game_active:
        # for the time being the context will reset to the players at the beginning of every loop
        context = HackingTeam.player
        decision_struct = {}
        exploit_details = {}
        capability_details = {}
        skill_requirements = {}
        cmd = ""

        try:
            cmd = input(f"[{context.name}] > ")
            if cmd.lower() == 'exit':
                decision = input(f"{context.name}, You're about to exit the game. Are you sure? [y|N] ")
                if (decision.lower() == 'y'):
                    exit(0)
        
            while "  " in cmd:
                cmd = cmd.replace("  ", "")
            cmd = cmd.lstrip().rstrip().replace('.','').replace(',','').split(' ')
            # this checks to see if the player addresses a specific npc
            # the second part checks if the player uses an abreviated name to address a npc
            if ((cmd[0].lower() in npc_names) or [s for s in npc_names if cmd[0].lower() in s]) and cmd[0] != '':
                targeted_npc_name = [s for s in npc_names if cmd[0].lower() in s].pop(0)
                if targeted_npc_name == HackingTeam.npc1.name:
                    context = HackingTeam.npc1
                elif targeted_npc_name == HackingTeam.npc2.name:
                    context = HackingTeam.npc2
                elif targeted_npc_name == HackingTeam.npc3.name:
                    context = HackingTeam.npc3
                else:
                    print("[!] ERROR: NPC name identified in inital command parsing, but couldn\'t determine which one.")
                    continue
                # this will remove the targeted npc from the cmd and allow the same code path to be used for the player and the npcs
                cmd.pop(0)

            # the context remains directed at the player object.

            decision_struct = {
                "decision_type": "",
                "context":"",
                "targetNetwork":"",
                "HackingTeam":"",
                "TargetSystem":"", # target system reference
                }

            if (cmd == []):
                getResponse(HackingTeam.player, context, 'blank_task')
                continue

                # Since I will start skipping over unknown words this will be the catch all and may have to be at the bottom.

            elif (cmd[0].lower() == "scan"):
                # syntax ex:
                # scan targets
                # scan segment from target X
                _ = cmd.pop(0)
                if (cmd == []):
                    print(f"[DEBUG] cmd: {cmd}")
                    getResponse(HackingTeam.player, context, 'blank_task')
                    continue
            
                elif [s for s in TargetNetwork.target_name_tracking if cmd[0].lower()+cmd[1] in s]:
                    target_ref = TargetNetwork._target_GetTargetReference(' '.join(cmd[0],cmd[1]))
                    target_ref.printTargetDetails()
                    continue

                elif cmd[0].lower() == "segment":
                    _ = cmd.pop(0)
                    _ = cmd.pop(0) # this will remote the "from" from the cmd.
                    if len(cmd) < 2:
                        print("[DEBUG] ERROR: length of scan segment cmd insufficient.")
                        continue
                    #cmd[0] = cmd[0][0].upper() + cmd[0][1:]
                    source_target_name = ' '.join([cmd[0].lower(),cmd[1]])
                    sufficient_source_access = False
                    if TargetNetwork._access_checkTargetNameValid(source_target_name):
                        if TargetNetwork._access_checkIfAccessIsAcquired(source_target_name):
                            capes_on_source = TargetNetwork._target_GetTargetReference(source_target_name)._access_CheckAccessMethod()
                            # after I exploit past a target capes_on_source == []
                            if len(capes_on_target) > 0:
                                for cape in capes_on_source:
                                    if (cape["subtype"] == 'rat') or (cape["subtype"] == 'beaconing') or (cape["subtype"] == 'triggerable'):
                                        sufficient_source_access = True
                
                    if not sufficient_source_access:
                        print("[DEBUG] No RAT or implant on pivot scan source system.")
                        continue

                    # 1. I need to call the TargetNetwork.results_enumerateNetworkSegment(source_target_name)
                    decision_struct["targetNetwork"] = TargetNetwork
                    targets = decision_struct["targetNetwork"].results_enumerateNetworkSegment(source_target_name)
                    # 2. display all of the new targets scanned.
                    for target in targets:
                        target.printTargetDetails()

                    continue

                # there needs to be a dict length check to see if there is a from and a target component to the scan request.
                elif ("target" not in cmd[0].lower()) and ("tgt" not in cmd[0].lower()) and ("t" not in cmd[0][0].lower()):
                    getResponse(HackingTeam.player, context, 'which_one')
                    continue
                else:

                    # This is able to extract the target number from the normal text input
                    cmd = ' '.join(cmd)
                    cmd = cmd.strip('target').strip('t').strip('tgt').strip(' ').split(' ')[0]
                
                    # check if team has redirector(s)
                    if HackingTeam.redirectors == 0:
                        print(f"[!] Your team's redirection pool is sitting at {HackingTeam.redirectors}.")
                        print('[!] Your team has no method of redirecting traffic to the target.')
                        print("\tYou must aquire some redirectors.")
                        continue

                    try:
                        # If the user does not provide a target number or if text is provided this cast to int()
                        # will fail and will trigger the restart of the loop.
                        print(f"[DEBUG] cmd: {cmd}")
                        int(cmd)
                    except:


                        #getResponse(HackingTeam.player, context, 'which_one')
                        decision_struct["context"] = context
                        decision_struct["targetNetwork"] = TargetNetwork
                        decision_struct["HackingTeam"] = HackingTeam
                        decision_struct["decision_type"] = Decision_logic.get_scan_network_external(decision_struct)
                        Decision_logic.baseDecisionHandler(decision_struct)
                        continue


                    decision_struct["context"] = context
                    decision_struct["targetNetwork"] = TargetNetwork
                    decision_struct["HackingTeam"] = HackingTeam
                    decision_struct["decision_type"] = Decision_logic.get_scan_system(decision_struct, target_details)
                    # cmd is the specific target number
                    decision_struct["TargetSystem"] = cmd
                
                    Decision_logic.baseDecisionHandler(decision_struct)

                    continue
            
            elif (cmd[0].lower() == "exploit") or (cmd[0].lower() == "pop"):
                _ = cmd.pop(0)
                print(f"[DEBUG] cmd: {cmd}")
                if (cmd == []) or (len(cmd) < 4):
                    print(f"[DEBUG] len(cmd): {len(cmd)}")
                    print(f"[DEBUG] cmd: {cmd}")
                    getResponse(HackingTeam.player, context, 'blank_task')
                    continue
            
                # ex. exploit|pop, target #, with exploit_SN, from target|redirector
                # The parsing will group with and exploit and from source...

                target_system = ' '.join([cmd[0], cmd[1]])
                _ = cmd.pop(0)
                _ = cmd.pop(0)

                exploit_sn = cmd[cmd.index('with')+1]
                _ = cmd.pop(cmd.index('with')+1)
                _ = cmd.pop(cmd.index('with'))
                source_system = ""
                if HackingTeam._cape_GetCapeSubtype(exploit_sn) == 'rce':
                    source_system = ' '.join(cmd[(cmd.index('from')+1):])
                    #list_index = cmd.index('from')
                    _ = cmd.pop(cmd.index('from'))

                # need to validate exploit SN/name
                if not HackingTeam._cape_validateCapeSn(exploit_sn):
                    print(f"[DEBUG] Invalid cape_sn.")
                    getResponse(HackingTeam.player, context, "which_one")
                    continue

                exploit_port = HackingTeam._cape_getCapePort(exploit_sn)
                if exploit_port == 0:
                    exploit_port = None

                exploit_details = {
                    "target": target_system,
                    "exploit_sn": exploit_sn,
                    "subtype": "",
                    "port": exploit_port,
                    "source_system": source_system,
                    "author_is_context": False,
                    "permissions":"",
                    "src_cape": "",
                    "instance_id":  context._access_GenereateAccessInstanceID(),
                    "src_instance_id": "",
                    }

                # 1. look to see if target name is registered in TargetNetwork.target_name_tracking
                # 2. iterate through the targets, check to see if it's visible, and check to see if the port being exploited is visible.
                if not TargetNetwork._exploit_checkIfValid(exploit_details):
                    print(f"[DEBUG] Exploit details are not valid.")
                    getResponse(HackingTeam.player, context, "cannot exploit")
                    continue


                # Start building the decision_struct here
                decision_struct["context"] = context
                decision_struct["targetNetwork"] = TargetNetwork
                decision_struct["HackingTeam"] = HackingTeam

                
                exploit_details['permissions'] = decision_struct["HackingTeam"]._cape_GetCapePermissions(exploit_details["exploit_sn"])
                decision_struct['TargetSystem'] = TargetNetwork._target_GetTargetReference(exploit_details['target'])
                capes_on_target = decision_struct['TargetSystem']._access_CheckAccessMethod()
                # There needs to be a check to make sure you're not re-thorwing an exploit. 
                #if decision_struct['TargetSystem']._access_CheckAccessLevel() != "tool"

                for cape in capes_on_target:
                    if cape['cape_sn'] == exploit_details['exploit_sn']:
                        print("[--] This exploit has already been successfully thrown at/on this target.")
                        continue

                exploit_details["subtype"] = HackingTeam._cape_GetCapeSubtype(exploit_details["exploit_sn"])
            
                # I'm not sure the exploit with LPE code works.
                if exploit_details["subtype"] == "lpe":
                    if decision_struct['TargetSystem'].access_acquired:
                        if capes_on_target == []:
                            print("[DEBUG] ERROR: You have access to the target, but no tools were identified as being on target.")
                            continue
                    else:
                        print("[--] You don't have access to this target.")
                        continue
                    permission_levels = ["user","limited service","system","kernel","vm break-in","vm break-out"]
                    for cape in capes_on_target:
                        if permission_levels.index(cape["permissions"]) >= permission_levels.index(exploit_details['permissions']):
                            print("[--] Current permission level on target already meets or exceedes the resulting permissions of this LPE.")
                            continue

                elif exploit_details["subtype"] not in PlayerUtils.exploit_sub_type_list:
                    print(f"[ERROR] tool type provided doesn't seem to be of type exploit.\n\tTool subtype provided is {exploit_details['subtype']}")
                    continue
                else:
                    # exploit sub_type is other than LPE
                    # 3. check if source is redirector or another target and do you have access to it via "access_acquired".
                    #       a. And that the level of target access is sufficient to laterlly move. 
                    if (exploit_details["source_system"] != "redirector") and (exploit_details["source_system"] != "rdr"):
                        if not TargetNetwork._access_checkTargetNameValid(exploit_details["source_system"]):
                            print(f"[DEBUG] Invalid source target")
                            getResponse(HackingTeam.player, context, "bad_exploit_source")
                            continue

                        if not TargetNetwork._access_checkIfAccessIsAcquired(exploit_details["source_system"]):
                            print(f"[DEBUG] Does not have access to source_system.")
                            getResponse(HackingTeam.player, context, "bad_exploit_source")
                            continue

                        if not decision_struct["targetNetwork"]._access_CheckInterTargetConnectivity(decision_struct['TargetSystem'].name,
                                                                                                     exploit_details["source_system"]):
                            print("[] The source and target system cannot communicate with each other.")
                            continue


                        # if the target being redirected through only has a single tool that can be used for pivoting than 
                        # this check will assign the cape_sn to exploit_details["src_cape"]
                        # If there are more than 1 cape on the pivot system that can be used for redirection than 
                        # the player will be prompted to make a decision on which tool will be routed through.
                        capes_on_source =  TargetNetwork._target_GetTargetReference(exploit_details["source_system"])._access_CheckAccessMethod()
                        #temp_capes_on_source = []
                        #for cape in capes_on_source:
                            #if (cape['subtype'] == "rat") or (cape['subtype'] == "beaconing") or (cape['subtype'] == "triggerable"):
                                #temp_capes_on_source.append(cape)
                        #capes_on_source = temp_capes_on_source

                        #exploit_details = _access_GetSourceCapeDetails(capes_on_source, exploit_details, decision_struct)
                        for index,cape in enumerate(capes_on_source):
                            if (cape["subtype"] == "beaconing") or (cape["subtype"] == "triggerable"):
                                has_implant_connection = False
                                for connection in decision_struct["context"].connected_targets:
                                    if connection["cape_sn"] == cape["cape_sn"]:
                                        has_implant_connection = True
                                if not has_implant_connection:
                                    capes_on_source.pop(index)
                            elif cape['type'] == "exploit":
                                if cape["subtype"] == 'rce':
                                    capes_on_source.pop(index)
                            else:
                                pass

                        if len(capes_on_source) < 1:
                            print(f"[DEBUG] ERROR: Target: {decision_struct['TargetSystem'].name} does not currently have any tools on target")
                            continue
                        elif len(capes_on_source) == 1:
                            if capes_on_source[0]["type"] == "exploit":
                                print(f"[DEBUG] ERROR: target only has an exploit currently present. You need to upgrade your access.")
                                continue
                            else:
                                exploit_details["src_cape"] = capes_on_source[0]["cape_sn"]
                                exploit_details["src_instance_id"] = capes_on_source[0]["instance_id"]

                        elif len(capes_on_source) > 1:
                            print(f"[-] There are multiple capes on the source system that can be used to pivot. Please choose a tool to redirect through.")
                            print("[-]  -  {subtype}:{cape_sn}, instance_id:{instance_id}")
                            for index, cape in enumerate(capes_on_source):
                                ###############################################
                                # This will print exploits and it should't
                                # I need to build another list and then select from that.
                                ###############################################
                                print(f"[{index+1}]  -  {cape['subtype']}:{cape['cape_sn']}, instance_id:{cape['instance_id']}")

                            while exploit_details["src_cape"] == "":
                                chosen_cape = input("[ ] source cape? ")
                                if chosen_cape.lower() == "cancel":
                                    break
                                int_cast_decision = 0
                                try:
                                    int_cast_decision = int(chosen_cape)
                                except Exception as ex:
                                    print(ex)
                                    continue

                                if 1 < int_cast_decision < (len(capes_on_source)):
                                    print(f"[DEBUG] ERROR: Decision is outside of the allowable range.")
                                    continue

                                else:
                                    exploit_details["src_cape"] = capes_on_source[int_cast_decision - 1]['cape_sn']
                                    exploit_details["src_instance_id"] = capes_on_source[int_cast_decision - 1]['instance_id']
                                    
                        elif len(capes_on_source) > 1:
                             exploit_details["src_instance_id"] = capes_on_source[0]['instance_id']
                            
                        else:
                            pass

                        if exploit_details["src_cape"] == "":
                            continue

                        capes_on_source = decision_struct["targetNetwork"]._target_GetTargetReference(exploit_details["source_system"])._access_CheckAccessMethod()
                        rat_or_implant_present_on_source = False
                        for cape in capes_on_source:
                            if (cape['subtype'] == 'rat') or (cape["subtype"] == "beaconing") or (cape["subtype"] == "triggerable"):
                                rat_or_implant_present_on_source = True

                        if not rat_or_implant_present_on_source:
                            print(f"[DEBUG] Implant or RAT not present on the target, but you're trying to exploit past this target.")
                            getResponse(HackingTeam.player, context, "bad_exploit_source")
                            continue

                    elif (exploit_details["source_system"] == "redirector") or (exploit_details["source_system"] == "rdr"):
                        if HackingTeam.redirectors <= 0:
                            print("[Narrator] Your team's redirector count is 0.")
                            continue
                        else:
                            if decision_struct['TargetSystem'].edge_node == False:
                                print("[ ] Failure to exploit target because it's ot externally accessable.")
                                continue

                    else:
                        print("[DEBUG] unexpected state in exploit source system validation checks.")
                        continue

                cape_owner =  HackingTeam._cape_GetCapeOwner(exploit_details["exploit_sn"])
                if cape_owner == "":
                    print(f"[DEBUG] ERROR: {exploit_details['exploit_sn']} was found in the hacking team's inventory, but the owning character could not be identified.")
                    continue
                elif cape_owner == context.name:
                    exploit_details["author_is_context"] = True
                else:
                    pass
      

                #print(f"[DEBUG] exploit_details[\"subtype\"] == {exploit_details['subtype']}")
                # this may be causing an error if the hacker who's inventory the tool is pulled from is burned out.

                #if exploit_details["subtype"] == "":
                    #exploit_details["subtype"] = HackingTeam._cape_GetCapeSubtype(exploit_details["exploit_sn"])
                    #print(f"[DEBUG] ERROR: {exploit_details['exploit_sn']} was found in the hacking team's inventory, but the subtype could not be deteremined.")
                    #continue

                # obtain failure narrative should occur inside the HackingTeam._values_ExploitTargetDecision()
                # failure_narrative = TargetNetwork._access_NarrativeCapeFailureCause(subtype)
                skill_requirements = HackingTeam._values_ExploitTargetDecision(exploit_details, decision_struct)

                decision_struct["decision_type"] = Decision_logic.get_exploit_system(decision_struct, exploit_details, skill_requirements)

                Decision_logic.baseDecisionHandler(decision_struct)

                continue

            # A system survey is done automatically by the hacker that gained access to that system.
            # I do not think the mechanics or game play for requiring a manual system survey would work out well.
            # The survey benefits can be made as a potential bonus in exploit/implant functions/task


            elif (cmd[0].lower() == "implant") or (cmd[0].lower() == "install") or (cmd[0].lower() == "upload"):
                # implant target 2/tgt with backdoor/tool SN/etc.
                _ = cmd.pop(0)
                if (cmd == []):
                    print(f"[DEBUG] cmd: {cmd}")
                    getResponse(HackingTeam.player, context, 'blank_task')
                    continue

                tool_details = {
                    "type": "",
                    "tool_sn": "",
                    "subtype": "",
                    "port": "",
                    "author_is_context": False,
                    "burned": bool,
                    "permissions": "",
                    "src_cape": "",
                    "instance_id": "",
                    "src_instance_id": "",
                    }

                # 1. parse out command
                tool_details["tool_sn"] = cmd[-1]
                target_system = ' '.join([cmd[0], cmd[1]])

                # 2. validate target
                if not TargetNetwork._access_checkTargetNameValid(target_system):
                    print(f"[DEBUG] Invalid target")
                    getResponse(HackingTeam.player, context, "idk") # Need to add a response type for this and change this call.
                    continue

                decision_struct['TargetSystem'] = TargetNetwork._target_GetTargetReference(target_system)
                # 3. validate cape
                if not HackingTeam._cape_validateCapeSn(tool_details["tool_sn"]):
                    print(f"[DEBUG] Invalid cape_sn")
                    getResponse(HackingTeam.player, context, "not_valid")
                    continue
            
                decision_struct["context"] = context
                decision_struct["HackingTeam"] = HackingTeam
                decision_struct["targetNetwork"] = TargetNetwork


                if decision_struct['TargetSystem'].type != decision_struct["HackingTeam"]._cape_GetCapePlatformType(tool_details["tool_sn"]):
                    print(f"[ERROR] The platform type of the capability ({decision_struct['HackingTeam']._cape_GetCapePlatformType(tool_details['tool_sn'])}) does not match that of the targeted system ({decision_struct['TargetSystem'].type}).")
                    continue

                tool_details["permissions"] = decision_struct["HackingTeam"]._cape_GetCapePermissions(tool_details["tool_sn"])
                tool_details["burned"] = decision_struct["HackingTeam"]._cape_GetCapeBurnedStatus(tool_details["tool_sn"])

                # 4. Validate that the hacker attempting to implent that target has access to that target.
                #   4a. check the target object 
                if not decision_struct['TargetSystem'].access_acquired:
                    print(f"[DEBUG] Target object shows access_acquired == False.")
                    getResponse(HackingTeam.player, context, "not_valid") # Need to add a response type for this and change this call.
                    continue
                #   4d. check the hacker object
                if not decision_struct["context"]._access_HasAccessToTarget(decision_struct['TargetSystem'].name):
                    print(f"[DEBUG] Hacker object does not contain that target name in it's list of connected target.")
                    getResponse(HackingTeam.player, context, "not_valid") # Need to add a response type for this and change this call.
                    continue
                #   4c. validate that the type of cape_sn being passed is a tool and not an exploit.

                

                # I need to check to make sure that there is a tool or capability with equal or greater permissions on that target
                capes_on_target = decision_struct['TargetSystem']._access_CheckAccessMethod()
                if capes_on_target == []:
                    print("[DEBUG] ERROR: You have access to the target, but no tools were identified as being on target.")
                    continue
                permission_levels = ["user","limited service","system","kernel"]
                perm_req_met = False
                for cape in capes_on_target:
                    if permission_levels.index(cape["permissions"]) >= permission_levels.index(tool_details["permissions"]):
                        perm_req_met = True
                if not perm_req_met:
                    print("[--] Current permission level on target does not meet the required minimum permission level.")
                    continue


                #

                #   4d. Need to check if triggerable implant is opening a port on an already bound port.
                tool_details["subtype"] = decision_struct["HackingTeam"]._cape_GetCapeSubtype(tool_details["tool_sn"])
                if tool_details["subtype"] == "triggerable":
                    tool_details["port"] = decision_struct["HackingTeam"]._cape_getCapePort(tool_details["tool_sn"])
                    if tool_details["port"] in decision_struct['TargetSystem'].openPorts:
                        print(f"[DEBUG] The port for the triggerable implant is already bound on that system.")
                        getResponse(HackingTeam.player, context, "not_valid")
                        continue

                if decision_struct["HackingTeam"]._cape_GetCapeOwner(tool_details["tool_sn"]) == decision_struct["context"].name:
                    tool_details["author_is_context"] = True

                target_connections = []
                connection_selection = ""
                if tool_details["subtype"] == 'rat':
                    for connection in context.connected_targets:
                        if ((connection['targeted_system'] == decision_struct['TargetSystem'].name) and ((connection['access_method'] == 'rat') or (connection['access_method'] == 'exploit') or (connection['access_method'] == 'beaconing') or (connection['access_method'] == 'triggerable'))):
                             target_connections.append(connection)
                    decision = 1
                    if target_connections != []:
                        if len(target_connections) > 1:
                            print(f"[!] There are mutiple tools accessing this target... Please choose 1 that is being used to upload this tool.")
                            for index, connection in enumerate(target_connections):

                                print(f"[{index+1}]")
                                print(f"\tSource system:  {connection['src']}")
                                print(f"\tSource Cape:    {connection['src_cape']}")
                                print(f"\targetd cape: {HackingTeam._cape_GetCapeSubtype(connection['cape_sn'])}:{connection['cape_sn']}")
                    
                            try:
                                decision = input("[?] Uploading tool selection? [#|cancel]")
                                if decision.lower() == "cancel":
                                    continue
                                int_decision = int(decision) - 1
                                if target_connections[int_decision]['access_method'] == "exploit":
                                    #connection_selection = target_connections[int_decision]
                                    connection_selection = deepcopy(target_connections[int(decision)-1])
                                else:
                                    connection_selection = deepcopy(target_connections[int_decision])

                            except Exception as ex:
                                print(ex)
                                continue

                        else:
                            #connection_selection = deepcopy(target_connections[0])
                            if target_connections[int(decision)-1]['access_method'] == "exploit":
                                #connection_selection = target_connections[int(decision)-1]
                                connection_selection = deepcopy(target_connections[int(decision)-1])
                            else:
                                connection_selection = deepcopy(target_connections[int(decision)-1])
                        
                        connection_selection["access_method"] = tool_details["subtype"]
                        connection_selection['cape_sn'] = tool_details["tool_sn"]
                        tool_details['instance_id'] = connection_selection['instance_id']
                        tool_details['src_instance_id'] = connection_selection['src_instance_id']


                access_struct = {
                    "context_name" :  decision_struct["context"].name,
                    "target_name" : decision_struct['TargetSystem'].name,
                    "access_method" : tool_details["subtype"],
                    "cape_sn": tool_details["tool_sn"],
                    "target_connection_details": connection_selection,
                    }
            
                skill_requirements = decision_struct["HackingTeam"]._values_DeployToolDecision(access_struct, tool_details, decision_struct)

                decision_struct["decision_type"] = Decision_logic.get_deploy_tool(decision_struct, tool_details, access_struct, skill_requirements)

                Decision_logic.baseDecisionHandler(decision_struct)

                continue

            # Need a task to connect to a target that has a beconing or triggerable implant present
            elif (cmd[0].lower() == "connect"):
                # triggerable: connect to <target #> from <target #|rdr>
                # beaconing: connect to <target #> // requires at least 1 redirector
                # connect via another hacker's access. ie. RAT or implant.

                # Expected syntax "connect to target X with <cape_sn>"
                _ = cmd.pop(0) # for command
                _ = cmd.pop(0) # for connecting word 'to'
                print(f"[DEBUG] cmd: {cmd}")
                if (cmd == []):
                    getResponse(HackingTeam.player, context, 'blank_task')
                    continue

                # check for overall length between 3 and 5
                if (len(cmd) < 3) or (len(cmd) > 6):
                    print(f"[DEBUG] Argument count to connect command outside of expected range: len(cmd): {len(cmd)}")
                    continue
                # grab the cape and target details 
                target_name = ' '.join(cmd[0:2])
                _ = cmd.pop(0) # removes 'target'
                _ = cmd.pop(0) # removes '#'
                _ = cmd.pop(0) # removes 'with
                target_ref = TargetNetwork._target_GetTargetReference(target_name)
                cape_sn = cmd[0]
                _ = cmd.pop(0) # this removs cape_sn
                # check if the cape is gtg 
                # check to make sure the cape is already on target and that the hacker isn't already connected.

                '''
                # do length check against the cmd var
                # on [port] [tcp|udp]
                triggerable_port_num = ""
                triggerlable_port_proto = ""
                if (len(cmd) > 0) and (len(cmd) < 3):
                    _ = cmd.pop(0) # removes 'on' from the line.
                    _ = cmd.pop(0) # this removes the string 'port' from the cmdline
                    triggerable_port_num = cmd.pop(0)
                    triggerlable_port_proto = cmd.pop(0).lower()
                    if (triggerlable_port_proto != 'tcp') or (triggerlable_port_proto != 'udp'):
                        print(f"[DEBUG] ERROR: {triggerlable_port_proto} is not a valid protocol when connecting to a triggerable implant.")
                        continue
                '''
                                



                ##########################
                # Need to add length check here for cmd to account for connecting into a triggerable implant from a pivot system.
                ##########################


                # 1. validate the used cape is legitimate
                if not HackingTeam._cape_validateCapeSn(cape_sn):
                    print(f"[DEBUG] Invalid cape_sn.")
                    getResponse(HackingTeam.player, context, "which_one")
                    continue

                connection_details = {
                    "cape_sn": cape_sn,
                    "type":"implant",
                    "subtype": HackingTeam._cape_GetCapeSubtype(cape_sn),
                    "burned": HackingTeam._cape_GetCapeBurnedStatus(cape_sn),
                    "port": None,
                    "permissions": HackingTeam._cape_GetCapePermissions(cape_sn),
                    "targeted_system": target_name,
                    "src_system": "",
                    "src_instance_id": "",                    }

                if len(cmd) == 0:
                    # 2. validate that the required tool is on the target
                    if not target_ref._access_IsCapePresent(cape_sn):
                        print(f"[DEBUG] Choosen cape ({cape_sn}) is not currently present on the targeted system.")
                        continue

                    # 3. validate that the hacker attempting to connect is not already connect via that cape_sn
                    connected_targets = context.connected_targets
                    already_connected = False
                    for target in connected_targets:
                        if ( target["targeted_system"] == target_name) and (target["cape_sn"] == cape_sn):
                            already_connected = True

                    if already_connected:
                        print(f"[DEBUG] This hacker is already connected to {target_name} with {cape_sn}")
                        continue

                    # 4. I need to check if the capability is a beconing implant.
                    if connection_details['subtype'] == "beaconing":
                        if HackingTeam.redirectors <= 0:
                            print("[DEBUG] Your attempt to connect into a beaconing implant failed because you've got no redirectors.")
                            continue
                        connection_details["src_system"] = "rdr"

                    #elif connection_details['subtype'] != "rat":
                        # triggerable occurs elsewhere in this function.
                        #print(f"[DEBUG] Attempting to connect to a cape that doesn't support the connect functionality.'")
                        #print(f"[DEBUG] Offending cape_sn: {cape_sn} and subtype: {connection_details['subtype']}.")
                        #continue                        
                    #else:
                        #print(f"[DEBUG] ERROR when attempting to execute a Connect task using {cape_sn} with a subtype of {connection_details['subtype']}.")
                        #continue


                
                # the parsing code for triggerable implants above needs to be integrated into the below branch
                elif len(cmd) > 2: # this will allow for "from rdr" and "from target #"
                    _ = cmd.pop(0)  # removes 'from'
                    connection_details['src_system'] = ' '.join(cmd)
                    if not TargetNetwork._access_checkTargetNameValid(connection_details['src_system']):
                        print(f"[ERROR] {connection_details['src_system']} is not a valid target.")
                        continue

                    # if triggerable
                    if connection_details["subtype"] == "triggerable":
                    #   if targeted system has tool specific port visible from src
                        openports = target_ref.openPorts
                        connection_details["port"] = HackingTeam._cape_getCapePort(cape_sn)
                        is_port_open_on_target = False
                        for port in openports:
                            if port == connection_details["port"]:
                                is_port_open_on_target = True

                        if not is_port_open_on_target:
                            print(f"[DEBUG] Triggerable implant port ({connection_details['port']}) not open on target")
                            continue
                    #   if src == rdr validate targeted system is edge node
                    if (connection_details['src_system'] == 'rdr') or (connection_details['src_system'] == 'redirector'):
                        if HackingTeam.redirectors <= 0:
                            print("[DEBUG] Your attempt to connect into a triggerable implant failed because you've got no redirectors.")
                            continue                    
                    #   if final [-2:] is target #

                    if not TargetNetwork._access_CheckInterTargetConnectivity(connection_details['src_system'], connection_details['targeted_system']):
                        print(f"[ERROR] {connection_details['src_system']} cannot reach {connection_details['targeted_system']}")
                        continue
                    
                    #source_access_verified = False
                    #src_instance_id = ""
                    routable_capes = []
                    capes_on_src = TargetNetwork._target_GetTargetReference(connection_details['src_system'])._access_CheckAccessMethod()
                    for cape in capes_on_src:
                        if cape['currently_present']:
                            if (cape["subtype"] == "rat") or (cape["subtype"] == "beaconing") or (cape["subtype"] == "triggerable"):
                                routable_capes.append(cape)
                                #source_access_verified = True
                                #break
                        # need to check if there is an active RAT or implant on target

                    if len(routable_capes) == 0:
                        print(f"[ERROR] The source target provided does not have either a RAT or implant currently loaded.")
                        continue           
                    elif len(routable_capes) == 1:
                        connection_details["src_instance_id"] = routable_capes[0]["instance_id"]

                    elif len(routable_capes) > 1:
                        print(f"[!] There are mutiple tools you can route your traffic through... Please choose one.")
                        for index, routable_cape in enumerate(routable_capes):

                            print(f"[{index+1}]")
                            print(f"\tSource system:  {connection['src']}")
                            print(f"\tSource Cape:    {connection['src_cape']}")
                            print(f"\targetd cape: {HackingTeam._cape_GetCapeSubtype(connection['cape_sn'])}:{connection['cape_sn']}")
                    
                        try:
                            decision = input("[?] Uploading tool selection? [#|cancel]")
                            if decision.lower() == "cancel":
                                continue
                            int_decision = int(decision) - 1
                            connection_details["src_instance_id"] = routable_cape["instance_id"]
                        except Exception as ex:
                            print(ex)
                            continue


                if connection_details["src_instance_id"] == "":
                    cape_instances_on_target = []
                    capes_on_tgt = TargetNetwork._target_GetTargetReference(connection_details['targeted_system'])._access_CheckAccessMethod()  
                    for cape in capes_on_tgt: 
                        if cape["cape_sn"] == connection_details['cape_sn']:
                            cape_instances_on_target.append(cape)
                    if len(cape_instances_on_target) == 0:
                        print("[ERROR] Tool was validated as present on targets, but for some reason failed this specific check for it's existance on target.")
                        continue

                    elif len(cape_instances_on_target) == 1:
                        connection_details["src_instance_id"] = cape_instances_on_target[0]["instance_id"]

                    elif len(cape_instances_on_target) < 1:
                        print(f"[!] There are mutiple instances of that tool on target... Please choose one.")
                        for index, cape in enumerate(cape_instances_on_target):

                            print(f"[{index+1}]")
                            print(f"\tSource system:  {connection['src']}")
                            print(f"\tSource Cape:    {connection['src_cape']}")
                            print(f"\targetd cape: {HackingTeam._cape_GetCapeSubtype(connection['cape_sn'])}:{connection['cape_sn']}")
                    
                        try:
                            decision = input("[?] Uploading tool selection? [#|cancel]")
                            if decision.lower() == "cancel":
                                continue
                            int_decision = int(decision) - 1
                            connection_details["src_instance_id"] = cape["instance_id"]
                        except Exception as ex:
                            print(ex)
                            continue


                # 5. append the connection to the hacker's connected_targets list


                access_method = ""
                if connection_details['type'] == 'exploit':
                    access_method = 'exploit'
                else:
                    access_method = connection_details['subtype']
                    
                target_connection_details = {
                    "src": connection_details['src_system'],
                    "src_cape": "",
                    "targeted_system" : connection_details['targeted_system'],
                    "access_method" : access_method,
                    "cape_sn": connection_details['cape_sn'],
                    "instance_id": "",
                    "src_instance_id": connection_details["src_instance_id"],
                    }

                for key, value in target_connection_details.items():
                    if value == "":
                        print(f"[DEBUG] ERROR: Constructing the hacker specific target_connection_details struct failed due to {key} == ''")
                        continue
                #if (target_connection_details["src"] == "") or (target_connection_details["targeted_system"] == "") or (target_connection_details["access_method"] or target_connection_details["cape_sn"]):
                #    print(f"[DEBUG] ERROR: Constructing the hacker specific target_connection_details struct failed due to an element being empty.")
                #    continue

                context._access_ConnectToTarget(target_connection_details)

                ## I NEED TO ADD CODE HERE THAT WILL ADD AN INSTANNCE ID TO THE TARGET TOOL DETAILS

                print(f"{context.name} is now connected to {target_connection_details['targeted_system']} via {target_connection_details['cape_sn']}")
                
                continue

            elif (cmd[0].lower() == "disconnect"):
                ''' task a hacker to disconnect from a specific target. Will cause an upstream disconnect. '''
               
                #1. take and parse user input
                #   [old] ex. disconnect [cape_sn] on [target_name]
                #   [new] ex. disconnect [instance_id] on [target_name]
                _ = cmd.pop(0) # removes 'disconnect'
                #cape_sn = cmd.pop(0) # This needs to change to instance ID.
                instance_id = cmd.pop(0)
                _ = cmd.pop(0) # removes the 'on'
                target_name = " ".join(cmd)
                _ = cmd.pop(0) 
                _ = cmd.pop(0)


                # I need to validate that the hacker requesting the disconnect is the hacker that holds the connection.
                target_connection_detected = False
                for target in context.connected_targets:
                    if target["targeted_system"] == target_name:
                        target_connection_detected = True
                        break
                if not target_connection_detected:
                    print(f"[ ] {context.name} is not connected to that target.")
                    continue

                #2. Need to validate the cape_sn and the target_name
                scope = ""
                cape_subtype = ""
                if instance_id == "all":
                    scope = "all"
                #elif not HackingTeam._cape_validateCapeSn(instance_id):
                #    print(f"[ ] ERROR: The cape_sn ({cape_sn}) is not valid.")
                elif context._access_ValidateUniquenessOfGeneratedInstanceID(instance_id):
                    print(f"[ ] ERROR: The instance_id ({instance_id}) is not valid.")
                    continue
                else:
                    scope = "individual"
                    #if HackingTeam._cape_GetCapeSubtype(cape_sn) in PlayerUtils.exploit_sub_type_list:
                    cape_sn = context._cape_GetCapeSnFromInstanceId(instance_id)
                    cape_subtype = HackingTeam._cape_GetCapeSubtype(cape_sn)
                    if cape_subtype == "":
                        print(f"[DEBUG] ERROR: cape_subtype returned was \"\". ")
                        continue


                if not TargetNetwork._access_checkTargetNameValid(target_name):
                    print(f"[ ] ERROR: The target_name ({target_name}) is not valid.")
                    continue

                if TargetNetwork._target_GetTargetReference(target_name)._access_IsInstancePresent(instance_id) and instance_id != "all":
                    print(f"[ ] ERROR: The instance_id ({instance_id}) is not currently present on {target_name}.")
                    continue

                #disconnect_struct = {
                #    "context": "", # this will be defined here
                #    "initial_target": "", # str(): this will be defined here
                #    "cape_sn": "", # This remains for compatability with the remove command
                #    "instance_id": "", # degined in the caller   
                #    "cape_type": exploit|implant, # this will be defined here
                #    "scope": [individual|all], # this will be defined here
                #    "affected_targets": [], # this is populated in the called function.
                #    "initiated_by": [system|player] # this will be defined here
                #    "removal" : False, # this is for the removal function and isn't used here, but must be present
                #}

                ## Before calling the disconnect functionlaity validate that the player wants to continue.

                selection = input(f"[?] Are you sure you wish to disconnect from {target_name}. [Y|n]")
                if (selection.lower() != 'y') and (selection.lower() != ''):
                    print("[ ] Exiting disconnect process.")
                    continue
                #3. 

                empty_list = []

                
                disconnect_struct = {
                    "context": context,
                    "initial_target": target_name, 
                    "cape_sn": "", 
                    "instance_id": instance_id,
                    "cape_type": cape_subtype,
                    "scope": scope, 
                    "affected_targets": empty_list, 
                    "initiated_by": "player",
                    "removal": False,
                }


                ret_status = _access_InitiateSystemDisconnect(HackingTeam, TargetNetwork, disconnect_struct)

                if ret_status:
                    ret_status = "successful"
                else:
                    ret_status = "failed"

                print(f"[ ] Disconnect status returned {ret_status}.")
                continue

            elif (cmd[0].lower() == "attack"):

                print("[!] Not implemented yet.")
                continue
            elif (cmd[0].lower() == "remove") or cmd[0].lower() == "uninstall":

                ''' This function will call the global disconnect function, but with a context that dictates a removal of the 
                tool               
                '''

                # ex. remove [cape_sn] from [target_name]
                _ = cmd.pop(0) # removes 'remove'
                cape_sn = cmd.pop(0) # moves cape_sn into 'cape_sn' var
                _ = cmd.pop(0) # removes 'from' from cmd
                target_name = " ".join(cmd)
                cmd = ""

                # I need to validate that the hacker requesting the disconnect is the hacker that holds the connection.
                target_connection_detected = False
                for target in context.connected_targets:
                    if target["targeted_system"] == target_name:
                        target_connection_detected = True
                        break
                if not target_connection_detected:
                    print(f"[ ] {context.name} is not connected to that target.")
                    continue

                #2. Need to validate the cape_sn and the target_name
                if not TargetNetwork._access_checkTargetNameValid(target_name):
                    print(f"[ ] ERROR: The target_name ({target_name}) is not valid.")
                    continue

                if not HackingTeam._cape_validateCapeSn(cape_sn):
                    print(f"[] ERROR: The cape_sn({cape_sn}) is invalid.")
                    continue

                if not TargetNetwork._target_GetTargetReference(target_name)._access_IsCapePresent(cape_sn):
                    print(f"[ ] ERROR: cape_sn ({cape_sn}) is not present on {target_name}.")

                cape_subtype = HackingTeam._cape_GetCapeSubtype(cape_sn)
                if cape_subtype == "":
                    print(f"[DEBUG] ERROR: cape_subtype returned was \"\". ")
                    continue

                instance_id = HackingTeam._cape_CheckForInstancesFromCapeSn(cape_sn, target_name)

                if instance_id != "":
                    print(f"[ ] {target_name}:{cape_sn} has active connections associated with it ({instance_id}).\n[ ] Please disconnect before removing tool.")
                    continue

                empty_list = []

                disconnect_struct = {
                    "context": context,
                    "initial_target": target_name, 
                    "cape_sn": cape_sn, 
                    "instance_id": instance_id,
                    "cape_type": cape_subtype,
                    "scope": "individual", 
                    "affected_targets": empty_list, 
                    "initiated_by": "player",
                    "removal": True,
                }

                ret_status = _access_InitiateSystemDisconnect(HackingTeam, TargetNetwork, disconnect_struct)
                if ret_status:
                    ret_status = "successful"
                else:
                    ret_status = "failed"

                print(f"[ ] Disconnect status returned {ret_status}.")
                continue


            elif (cmd[0].lower() == "develop") or (cmd[0].lower() == "dev"):
                ## CLI syntax ex.:
                # dev windows triggerable 12345 tcp
                # dev windows rce 443 tcp


                _ = cmd.pop(0)
                print(f"[DEBUG] cmd: {cmd}")
                if (cmd == []):
                    getResponse(HackingTeam.player, context, 'blank_task')
                    continue

                if len(cmd) < 2:
                    print(f"[DEBUG] cmd: {cmd} ")
                    getResponse(HackingTeam.player, context, 'blank_task')
                    continue


                # adding the tool to the context and the team needs to be defered
                # to the background worker because it's dependant on a successful roll.
                capability_details = {
                    "cape_category":"",
                    "cape_type": "",
                    "bonus_type": "",
                    "platform": "",
                    "port": None,
                    "name": None,
                    "burned": False,
                    "permissions": "",
                    }

                platform = ""
                # [exploit], platform_os, (rce|lpe|lateral), [port]
                if (cmd[0].lower() == 'exploit') or [s for s in PlayerUtils.exploit_sub_type_list if cmd[1].lower() in s]:
                    capability_details["cape_category"] = "exploit"
                    if cmd[0].lower() == 'exploit':
                        _ = cmd.pop(0)
                    platform = cmd[0].lower()
                    _ = cmd.pop(0)
                    capability_details["cape_type"] = cmd[0]
                    if cmd[0].lower() == 'rce':
                        _ = cmd.pop(0)
                        # This currently can store "port" as the exploits port number....
                        if cmd[0].lower() == "port":
                            _ = cmd.pop(0)
                        #capability_details["port"] = cmd[0]
                        # cmd[0] = port number 
                        # cmd[1] = proto [tcp|udp]
                        capability_details["port"] = (cmd[0],cmd[1].lower())
                        _ = cmd.pop(0)
                        _ = cmd.pop(0)

                        if (capability_details["port"] != 'tcp') or (capability_details["port"] != 'udp'):
                            print("[ ] invalid protocol provided.")
                
                    if context._coinFlip() == 0:
                        capability_details["bonus_type"] == "exploit_development"
                    else:
                        capability_details["bonus_type"] == "scripting"

                # [payload|tool], platform_os, (triggerable|beaconing|etc), [port]
                elif (cmd[0].lower() == 'payload') or (cmd[0].lower() == 'tool') or ([s for s in PlayerUtils.tool_type_list if cmd[1].lower() in s]):
                    capability_details["cape_category"] = "tool"
                    if (cmd[0].lower() == 'payload') or (cmd[0].lower() == 'tool'):
                        _ = cmd.pop(0)
                    platform = cmd[0].lower()
                    _ = cmd.pop(0)
                    capability_details["cape_type"] = cmd[0]
                    if cmd[0].lower() == 'triggerable': 
                        _ = cmd.pop(0)
                        #capability_details["port"] = cmd[0]
                        capability_details["port"] = (cmd[0],cmd[1])
                        _ = cmd.pop(0)
                        _ = cmd.pop(0)

                    if context._coinFlip() == 0:
                        capability_details["bonus_type"] == "programming"
                    else:
                        capability_details["bonus_type"] == "scripting"


                else:
                    getResponse(HackingTeam.player, context, 'blank_task')
                    continue

                if ('win' in platform) or ('windows' in platform):
                    platform = 'windows'
                elif ('nix' in platform) or ('linux' in platform):
                    platform = 'linux'
                elif ('embed' in platform) or ('embedded' in platform):
                    platform = 'embedded'
                elif ('rtr' in platform) or ('router' in platform):
                    platform = 'router'
                elif ('fw' in platform) or ('firewall' in platform):
                    platform = 'firewall'
                else:
                    getResponse(HackingTeam.player, context, 'blank_task')
                    continue

                capability_details["platform"] = platform

                decision_struct["context"] = context
                decision_struct["targetNetwork"] = TargetNetwork
                decision_struct["HackingTeam"] = HackingTeam
                if capability_details["cape_category"] == 'exploit':
                    decision_struct["decision_type"] = Decision_logic.get_develop_capability(decision_struct, capability_details, HackingTeam._values_exploitDevelopmentDecision(capability_details["cape_type"]))
                elif capability_details["cape_category"] == 'tool':
                    decision_struct["decision_type"] = Decision_logic.get_develop_capability(decision_struct, capability_details, HackingTeam._values_toolDevelopmentDecision(capability_details["cape_type"]))
                else:
                    getResponse(HackingTeam.player, context, 'not_valid')
                    continue

                Decision_logic.baseDecisionHandler(decision_struct)

                continue



                #_ = cmd.pop(0)
                #print(f"[DEBUG] cmd: {cmd}")
                #if (cmd == []):
                #    print("[DEBUG] required more args, but nothing passed")
                #    continue
            
                #print("[!] Not implemented yet.")
                #continue

            #elif (cmd[0].lower() == "acquire"):
            elif (cmd[0].lower() == "get"):
                _ = cmd.pop(0)
                print(f"[DEBUG] cmd: {cmd}")
                if (cmd == []):
                    getResponse(HackingTeam.player, context, 'blank_task')
                    continue

                elif ('redirector' in cmd[0].lower()) or ('redir' in cmd[0].lower()) or ('rdr' in cmd[0].lower()):
                    decision_struct["context"] = context
                    decision_struct["HackingTeam"] = HackingTeam
                    decision_struct["decision_type"] = Decision_logic.get_acquire_redirector(decision_struct)
                    Decision_logic.baseDecisionHandler(decision_struct)
                    continue

                elif (cmd[0].lower() == "message"):
                    _ = cmd.pop(0)
                    if (cmd == []):
                        if HackingTeam._message_getNumberOfMessages() > 0:
                            print(HackingTeam._message_getMessageFromQueue())
                            continue
                        else:
                            print("[Narrator] There are no messages in the queue.")
                    elif (cmd[0].lower() == "count"):
                        print(f"There are {HackingTeam._message_getNumberOfMessages()} messages in the queue.")
                        continue

                else:   
                    print("[!] Not implemented yet.")
                    continue

            elif (cmd[0].lower() == "show"):
                _ = cmd.pop(0)
                if (cmd == []):
                    getResponse(HackingTeam.player, context, 'blank_task')
                    continue
                elif (cmd[0].lower() == 'team'):
                    print("\n"+r"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
                    print("\t\\\\\\\\\\\\\\ TEAM DETAILS \\\\\\\\\\\\\\")
                    print(r"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
                    team_list = HackingTeam.getTeamList()
                    print("-- Team Details:")
                    print(f"\t\___ Redirector Count: {HackingTeam.redirectors}")
                    print("\t\___ Team Members:")
                    for member in team_list:
                        print(f"\t-- Name: {member.name}")
                        print(f"\t  \___ Burned Out: {member.burnedout}")
                        print(f"\t  \___ Task Timer: {int(member.encumbered_timer_seconds/60)}m{member.encumbered_timer_seconds%60}s")
                        print(f"\t  \___ P: {member.programming}, S: {member.scripting}, NE: {member.network_exploitation}, ED: {member.exploit_development}, PER: {member.personality_bonus}")
                        #print(f"\t    \___ Programming: {member.programming}")
                        #print(f"\t    \___ Scripting: {member.scripting}")
                        #print(f"\t    \___ Network Exploitation: {member.network_exploitation}")
                        #print(f"\t    \___ Exploit Development: {member.exploit_development}")
                        #print(f"\t    \___ Personality Bonus: {member.personality_bonus}")
                        print(f"\t    \___ Targets:")
                        for target in member.connected_targets:
                            print(f"\t      \___ src: {target['src']}, target: {target['targeted_system']}, meth: {target['access_method']}({target['cape_sn']}), instance_id: {target['instance_id']}, src_instance_id: {target['src_instance_id']}")
                        print(f"\t    \___ Capabilities:")
                        if len(member.tools) > 0:
                            print("\t         \___ Tools:     TYPE  | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSINOS")
                            for tool in member.tools:
                                print("\t\t           \___  {0:5} | {1:14} | {2:6}  | {3:16} | {4:8} | {5:6} | {6:11}".format(tool["type"],tool["sub_type"],tool["name"],str(tool["port"]),tool["platform_type"],str(tool["burned"]),tool["permissions"]))
                                #print(f"\t         \___ Tools: {tool}")
                                #print(f"         \___ Tools: {member.tools}")
                        if (len(member.tools) > 0) and (len(member.exploits) > 0):
                            print("\t\t \____________________________________________________________________________________________________")
                            print("\t\t                                                                                                      \\")
                        if len(member.exploits) > 0:
                            print("\t         \___ Exploits: TYPE   | SUBTYPE        | CAPE_SN | PORT             | PLATFORM | BURNED | PERMISSIONS")
                            for exploit in member.exploits:
                                print("\t\t          \___ {0:5} | {1:14} | {2:6}  | {3:16} | {4:8} | {5:6} | {6:11}".format(exploit["type"],exploit["sub_type"],exploit["name"],str(exploit["port"]),exploit["platform_type"],str(exploit["burned"]),exploit["permissions"]))
                                #print(f"\t         \___ Exploits: {exploit}")
                            #print(f"         \___ Exploits: {member.exploits}")

                    print(r"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
                    print("\t///////      END     ///////")
                    print(r"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"+"\n")
                    continue
            
                elif (cmd[0].lower() == 'scan'):
                    # This may need to be moved under the 'target' section so that so it flows more with natural text.
                    # 'show target 1 scan' instead of show scan target 1
                    _ = cmd.pop(0)
                    if (cmd == []):
                        getResponse(HackingTeam.player, context, 'which_one')
                        continue
                elif (cmd[0].lower() == 'targets'):
                    # This will eventually call the targetnetwork render network map method
                    # this will not accurately depict targets once initial access to the network is obtained and
                    #   the representation of internal archetecture details
                    TargetNetwork.results_targetList()
                    continue

                print("[!] Unknown Command.")
                continue

            else:
                getResponse(HackingTeam.player, context, 'idk')
                continue

                # This may need to not give a response and simply pop the word off the stentence list.
        except Exception as ex:
            print(ex)
            continue
        # natural speech like text will be parsed in a somewhat contrived manner. 
    return

def getResponse(Player, context, response_type):
    ''' This is a GP NPC chat response retrieval func. '''
    if context == Player:
        print("[Narrator] No valid option or tasking commmand supplied.")
    else:
        response = context.getTaskingAcknowledgementResponse(response_type)
        print(f"[{context.name}] {response}")


def _access_InitiateSystemDisconnect(HackingTeam, TargetNetwork, disconnect_struct) -> bool:
    ''' This state can be called to indicate a target reboot, disconnect as a part of a failure, or player initiated'''

    
    '''
    # This function expects the calling function to pass a structure of this format.
    disconnect_struct = {
        "context": "", # this will be defined by the calling function
        "initial_target": "", # str(): this will be defined by the calling function
        "cape_sn": "", # this will be defined in the calling function
        "cape_type": exploit|implant, # this will be defined in the calling function
        "scope": [individual|all], # this will be defined by the calling function
        "affected_targets": [], # this is defined below.
        "initiated_by": [system|player] # this will be defined by the calling function
        "removal" : False, # this is for the removal function. Must be present from any caller
    }
    '''

    #if disconnect_struct['cape_type'] in PlayerUtils.exploit_sub_type_list:
        # call TargetNetwork, get a target reference and disconnect that 
        #pass

    # Every time there is a disconnect task ran that command ran against the player will get a list back
    # that list will be used to reach out to the TargetNetwork object and disconnect those targets & cape_sn
    #else:
    if disconnect_struct['scope'] == 'individual':
        print(f"[DEBUG] Disconnecting {disconnect_struct['context'].name} from {disconnect_struct['initial_target']}")
        #disconnect_struct['affected_targets'] = disconnect_struct['context']._access_DisconnectFromTarget_SinglePlayer(disconnect_struct['intial_target'])
        disconnect_struct['affected_targets'] = HackingTeam._access_DisconnectFromTarget_AllPlayers(disconnect_struct['initial_target'], disconnect_struct['instance_id'])
    elif (disconnect_struct['scope'] == 'all') and (disconnect_struct['initiated_by'] == 'player'):
        # This is equivilant to a disconnect all tools on target and everyone connected to them. 
        print(f"[DEBUG] Disconnecting all team members from {disconnect_struct['initial_target']}")
        disconnect_struct['affected_targets'] = HackingTeam._access_DisconnectFromTarget_AllPlayers(disconnect_struct['initial_target'], disconnect_struct['instance_id'])




    #######
    # The disconnect_struct['affected_targets'] contains cape_sns that the hacker is tracking as being connected.
    #   when the game goes through and modifies the hacker's connected states it snags the structure from that 
    #   hacker object.
    #   - the game takes that list of targets and capes and passes it to the TargetNetwork object
    #   - the TargetNetwork object then runs through all the targets and makes target specific modifications
    #       based on the target name and cape_sn passed in the list. 
    #   - this should scale the modifications to only the applicalbe systems.
    #######



    ##########
    # 1. 
    # 2. Need to disconnect the target reference
    if disconnect_struct['affected_targets'] == []:
        dummy_instance = {
            'src': "",
            'src_cape': "",
            'targeted_system': disconnect_struct['initial_target'],
            'access_method': "",
            'cape_sn': disconnect_struct['cape_sn'],
            'instance_id': "",
            'src_instance_id': "",
            }

        disconnect_struct['affected_targets'].append(dummy_instance)
    #    print("[!] ERROR: List of affected systems is empty and shouldn't be.")
    #    return False

    # this is failing to remove all capes in a disconnect 'all' scenerio.
    # the access level is tracked via on 1 connected tool so only that is 
    # passed in the loop below.
    # -- maybe implement an inital disconnect all task for the initial target
    #   so all items are disconnected. this would include an extract dict element called
    #   scope so that "individal" an "all" can bechecked in the Disconnect..._General()

    print(f"[DEBUG] disconnect_struct values: \n{disconnect_struct}")

    for target in disconnect_struct['affected_targets']:
        target_disconnect_struct ={
            "target": target["targeted_system"],
            "cape_sn": target["cape_sn"],
            "src_system": target["src"],
            # src_cape throws an error when disconnecting from a session connected to a beaconing implant.
            "src_cape": target["src_cape"],
            "instance_id": target["instance_id"],
            "src_instance_id": target["src_instance_id"],
            "port": HackingTeam._cape_getCapePort(target["cape_sn"]),
            }

        if (disconnect_struct['initial_target'] == target['targeted_system']) and (disconnect_struct['cape_sn'] == target['cape_sn']) and (disconnect_struct['removal'] == True):
            ret_status = TargetNetwork._access_DisconnectFromTarget_General(target_disconnect_struct)
            if ret_status:
                print(f"[ ] Disconnect from {target_disconnect_struct['target']} successful.")
            else:
                print(f"[ ] Disconnect from {target_disconnect_struct['target']} failed.")
        elif (disconnect_struct['cape_type'] not in PlayerUtils.tool_type_list) or ((disconnect_struct['cape_type'] == 'rat') and (disconnect_struct['instance_id'] == target['instance_id'])) or (target['access_method'] == 'exploit'):
            ret_status = TargetNetwork._access_DisconnectFromTarget_General(target_disconnect_struct)
            if ret_status:
                print(f"[ ] Disconnect from {target_disconnect_struct['target']} successful.")
            else:
                print(f"[ ] Disconnect from {target_disconnect_struct['target']} failed.")
        elif (disconnect_struct['cape_type'] not in PlayerUtils.tool_type_list) or (disconnect_struct['cape_type'] == 'rat') or (target['access_method'] == 'exploit'):
            ret_status = TargetNetwork._access_DisconnectFromTarget_General(target_disconnect_struct)
            if ret_status:
                print(f"[ ] Disconnect from {target_disconnect_struct['target']} successful.")
            else:
                print(f"[ ] Disconnect from {target_disconnect_struct['target']} failed.")


        else:
            print(f"[ ] Disconnected from {target_disconnect_struct['target']}, but {HackingTeam._cape_GetCapeSubtype(target['cape_sn'])}:{target['cape_sn']} was left.")

    #
    #
    ##########


    return True

'''
def _access_GetSourceCapeDetails(capes_on_source: list, exploit_details: dict, decision_struct: dict) -> dict:
    exploit_details['src_cape'] = ""
    exploit_details["src_instance_id"] = []
    if len(capes_on_source) < 1:
        print(f"[DEBUG] ERROR: Target: {decision_struct['TargetSystem'].name} does not currently have any tools on target")
        return exploit_details
    elif len(capes_on_source) == 1:
        if capes_on_source[0]["type"] == "exploit":
            print(f"[DEBUG] ERROR: target only has an exploit currently present. You need to upgrade your access.")
            return exploit_details
        else:
            exploit_details["src_cape"] = capes_on_source[0]["cape_sn"]
            exploit_details["src_instance_id"] = capes_on_source[0]["instance_id"]
            return exploit_details
    elif len(capes_on_source) > 1:
        print(f"[-] There are multiple capes on the source system that can be used to pivot. Please choose a tool to redirect through.")
        print("[-]  -  {subtype}:{cape_sn}, instance_id:{instance_id}")
        for index, cape in enumerate(capes_on_source):
            ###############################################
            # This will print exploits and it should't
            # I need to build another list and then select from that.
            ###############################################
            print(f"[{index+1}]  -  {cape['subtype']}:{cape['cape_sn']}, instance_id:{cape['instance_id']}")

        while exploit_details["src_cape"] == "":
            chosen_cape = input("[ ] source cape? ")
            if chosen_cape.lower() == "cancel":
                return exploit_details
            int_cast_decision = 0
            try:
                int_cast_decision = int(chosen_cape)
            except Exception as ex:
                print(ex)
                return exploit_details

            if 1 < int_cast_decision < (len(capes_on_source)):
                print(f"[DEBUG] ERROR: Decision is outside of the allowable range.")
                return exploit_details

            else:
                exploit_details["src_cape"] = capes_on_source[int_cast_decision - 1]['cape_sn']
                exploit_details["src_instance_id"] = capes_on_source[int_cast_decision - 1]['instance_id']
                                    
    elif len(capes_on_source) > 1:
            exploit_details["src_instance_id"] = capes_on_source[0]['instance_id']
                            
    else:
        pass
        return exploit_details
'''



if __name__ == "__main__":
    introBanner()
    input("[ ] Press the 'Enter' to play.")
    MainGameLoop()
