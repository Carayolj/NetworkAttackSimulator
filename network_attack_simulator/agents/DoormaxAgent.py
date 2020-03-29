import random
import time

import numpy as np

from network_attack_simulator.agents.agent import Agent
from network_attack_simulator.doormax.graphs import *
from network_attack_simulator.doormax.predictions import *
from network_attack_simulator.envs.action import Action


class DoormaxAgent(Agent):

    def __init__(self, adress_space, nService, topology,
                 action_space=[("scan", ["adress"]), ("exploit", ["adress", "service"])], k=3, knowledge={},
                 experience=[]):
        # self.lookUp = {}
        # self.lookUp[str(SMAX.write_pickle())]=SMAX
        self.gamma = 0.9
        self.action_space = action_space
        self.adress_space = adress_space
        self.true_topology = topology
        self.nService = nService
        self.new_state_value = 0
        self.V = defaultdict(lambda: self.new_state_value)
        self.experience = experience
        obs = OrderedDict()
        self.valueSMAX=1000
        for adress in self.adress_space:
            machine_state = OrderedDict()
            machine_state['compromised'] = True
            machine_state['reachable'] = True
            for service in range(self.nService):
                machine_state[service] = -1
            obs[adress] = machine_state
        self.keySMAX = State(obs)
        self.V[self.keySMAX] = 1000

        nets = len(set([a for a, _ in adress_space]))
        self.topology_knowledge = []
        for i in range(nets + 1):
            temp = []
            for j in range(nets + 1):
                if i == j:
                    temp += [1]
                else:
                    temp += [2]
            self.topology_knowledge += [temp]
        self.topology_knowledge[0] = self.true_topology[0]
        for a in range(len(self.topology_knowledge[0])):
            if self.topology_knowledge[0][a] == 1:
                self.topology_knowledge[a][0] = 1
            else:
                self.topology_knowledge[a][0] = 0

        self.k = k
        if knowledge != {}:
            self.knowledge = knowledge
        else:
            self.knowledge = {"pred": {}, "failure": {}}
            for a in self.action_space:
                self.knowledge['pred'][a[0]] = []
                self.knowledge['failure'][a[0]] = []

            # self.knowledge =
    def updateValid(self):
        #if pred.effect is None:
        #    ktype='failure'
        #else:
        #    ktype='pred'
        #for p in self.knowledge[ktype][a.type]:
        #    if matches(model,p):
        #        index=self.knowledge[ktype][a.type].index(p)
        for s,a,new_s in self.experience:
            if not equals(new_s,self.predictTransition(s,a)):
                return False
        return True



    def reset_topology_knowledge(self):
        nets = len(set([a for a, _ in self.adress_space]))
        self.topology_knowledge = []
        for i in range(nets + 1):
            temp = []
            for j in range(nets + 1):
                if i == j:
                    temp += [1]
                else:
                    temp += [2]
            self.topology_knowledge += [temp]
        self.topology_knowledge[0] = self.true_topology[0]
        for a in range(len(self.topology_knowledge[0])):
            if self.topology_knowledge[0][a] == 1:
                self.topology_knowledge[a][0] = 1
            else:
                self.topology_knowledge[a][0] = 0

    def show_knowledge(self):

        for action in self.knowledge.keys():
            for pred in self.knowledge[action]:
                temp = deepcopy(pred.model)
                SourceCandidates = get_refering_object(pred.model, pred.effect.source, pred.parameter)
                DestCandidates = get_refering_object(pred.model, pred.effect.source, pred.parameter)
                edges = new_s.es.select(_between=(set(SourceCandidates), set(DestCandidates)))
                for e in edges:
                    temp.es[e.index]['width'] = 4
                    temp.es[e.index]['color'] = 'blue'
                show(temp)

    def test(self, env):
        s0 = env._generate_initial_state()
        s0_processed = self._process_state(s0, update_knowledge=True)

        a1 = Action((1, 0), 1)
        s1, _, _ = env.step(a1)
        s1_processed = self._process_state(s1, update_knowledge=True)
        self.addExperience(s0_processed, a1, s1_processed)

        a2 = Action((1, 0), 1, service=0, type="exploit")
        s2, _, _ = env.step(a2)
        s2_processed = self._process_state(s2, update_knowledge=True)
        self.addExperience(s1_processed, a2, s2_processed)

        a3 = Action((2, 0), 1)
        s3, _, _ = env.step(a3)
        s3_processed = self._process_state(s3, update_knowledge=True)
        self.addExperience(s2_processed, a3, s3_processed)

        a4 = Action((2, 0), 1, service=0, type="exploit")
        s4, _, _ = env.step(a4)
        s4_processed = self._process_state(s4, update_knowledge=True)
        self.addExperience(s3_processed, a4, s4_processed)

        a5 = Action((3, 0), 1)
        s5, _, _ = env.step(a5)
        s5_processed = self._process_state(s5, update_knowledge=True)
        self.addExperience(s4_processed, a5, s5_processed)

        a6 = Action((3, 0), 1, service=0, type="exploit")
        s6, _, _ = env.step(a6)
        s6_processed = self._process_state(s6, update_knowledge=True)
        self.addExperience(s5_processed, a6, s6_processed)
        print('here')

        self.reset_topology_knowledge()

        s0 = env.reset()  # env._generate_initial_state()
        s0_processed = self._process_state(s0)

    def get_true_predictions(self):
        color_dict = {"network": "blue", "machine": "green", "hacker": "red", "vuln": "orange", "adress": "yellow"}
        modelGraphScanExposed = Graph()
        modelGraphScanExposed.add_vertex("H", classe="hacker")
        modelGraphScanExposed.add_vertex("N", classe="network")
        modelGraphScanExposed.add_vertex("M", classe="machine")
        modelGraphScanExposed.add_vertex("A", classe="adress")
        modelGraphScanExposed.add_vertex("V", classe="vuln")
        for v in modelGraphScanExposed.vs:
            v["color"] = color_dict[c]
        modelGraphScanExposed.add_edge("H", "N", connected=True)
        modelGraphScanExposed.add_edge("N", "M", belongs_to=True)
        modelGraphScanExposed.add_edge("A", "M", has_adress=True)
        modelGraphScanExposed.add_edge("M", "V", is_vuln="Unknown")

        modelGraphScan = Graph()
        modelGraphExploitExposed = Graph()
        modelGraphScanExposed.add_vertex("H", classe="hacker")
        modelGraphScanExposed.add_vertex("N", classe="network")
        modelGraphScanExposed.add_vertex("M", classe="machine")
        modelGraphScanExposed.add_vertex("A", classe="adress")
        modelGraphScanExposed.add_vertex("V", classe="vuln")
        for v in modelGraphScanExposed.vs:
            v["color"] = color_dict[c]
        modelGraphScanExposed.add_edge("H", "N", connected=True)
        modelGraphScanExposed.add_edge("N", "M", belongs_to=True)
        modelGraphScanExposed.add_edge("A", "M", has_adress=True)
        modelGraphScanExposed.add_edge("M", "V", is_vuln=True)

        modelGraphExploit = Graph()

    def train(self, env, num_episodes=100, max_steps=100, timeout=None, verbose=False, **kwargs):
        # self.test(env)
        knowledgeUpdated = True
        visualize = False
        if kwargs['knowledge'] is not None:
            self.knowledge = kwargs['knowledge']
        if kwargs['visualize'] is not None:
            visualize = kwargs['visualize']
        if kwargs['experience'] is not None:
            self.experience = kwargs['experience']
        if kwargs['training'] is not True:
            self.new_state_value = 2000
            self.valueSMAX=0
        episodes_times = []
        episodes_rewards = []
        episode_steps = []
        for episode in range(num_episodes):
            episode_start_time = time.time()
            if not knowledgeUpdated:
                break
            done = False
            step = 0
            ep_reward = 0
            max_steps = 100
            env._generate_initial_state()
            s = env.reset()
            self.reset_topology_knowledge()
            print("================================================")
            print("New episode")
            print("================================================")

            #            print(s)
            s = self._process_state(s)
            # show(s,visualize=True)
            actions_taken = []
            while not done:
                print("------------------------------------------------------")
                print("New step")

                start = time.time()
                a = self.policy(s)  # policy(s)
                policy_time = time.time()
                print("Time to compute policy:", policy_time - start)
                new_s, reward, done = env.step(a)
                new_s = self._process_state(new_s, update_knowledge=True)
                strAc=str(a.type)+' '+str(a.target)
                if a.type=='exploit':
                    strAc+=' '+str(a.service)
                show(new_s, visualize, 'current state (t='+str(step)+')\n'+"Previous action: "+strAc)
                if kwargs['training']:
                    knowledgeUpdated = self.addExperience(s, a, new_s, visualize=visualize)
                else:
                    actions_taken += [a]
                    for b in actions_taken:
                        print(b)
                    if equals(s,new_s):
                        print('faaaaaaaaaaaaaaaaaaaaaiiiil')
                add_experience_time = time.time()
                print("Time to add experience:", add_experience_time - policy_time)
                # self.showKnowledge()
                self.experience += [(s, a, new_s)]
                self.updateValues(new_s, env)
                value_time = time.time()
                print("Time to udate state values:", value_time- add_experience_time)
                if step == max_steps:
                    done = True
                step += 1
                ep_reward += reward
                s = new_s
                if done == True:
                    print(
                        "\n\n=============================================\n Episode ended\n=============================================")
                    print("Total reward:", ep_reward)
                    episode_time = time.time() - episode_start_time
                    episode_steps += [step]
                    episodes_rewards += [ep_reward]
                    episodes_times += [episode_time]
                elapsed = time.time() - start
                print("Loop time:", elapsed)
        return episode_steps, episodes_rewards, episodes_times

    def random_policy(self, s):
        candidates = []
        for a, _ in self.action_space:
            for add in self.adress_space:
                if a == 'exploit':
                    for v in range(self.nService):
                        candidates += [Action(add, 1, type='exploit', service=v)]
                else:
                    candidates += [Action(add, 1)]

        return np.random.choice(candidates)

    def policy(self, s, training=True):
        candidates = {}
        values = {}
        for t, classParam in self.action_space:
            candidates[t] = {}
            if t == "exploit":
                for addr in self.adress_space:
                    for serv in range(self.nService):
                        a = Action(addr, 1.0, service=serv, type="exploit")
                        candidates[t][(addr, serv)] = self.predictTransition(s, a)
            elif t == "scan":
                for addr in self.adress_space:
                    a = Action(addr, 1.0)
                    candidates[t][addr] = self.predictTransition(s, a)
        flatCandidates = {}
        for i in list(candidates.keys()):
            for j in list(candidates[i].keys()):
                flatCandidates[(i, j)] = candidates[i][j]
        for k in flatCandidates.keys():
            if equals(flatCandidates[k], s):
                values[k] = -1000
            elif flatCandidates[k] == SMAX:
                values[k] = self.valueSMAX
            else:
                values[k] = self.V[rebuild_state(flatCandidates[k], self)]
        print('_________________________________________________\nValues:')
        for (ty,arg),(val) in values.items():
            if val==self.new_state_value:
                prompt='a known effect'
            elif val==self.valueSMAX:
                prompt='an unknown effect'
            elif val==-1000:
                prompt='no effect'
            else:
                prompt='a known effect, but I can\'t predict for the following state'
            if ty=='scan':
                addr=arg
                print("Scanning adress",addr,"will have",prompt)
            elif ty=='exploit':
                addr,serv=arg
                print("Exploiting service ",serv," on adress ",addr," will have ",prompt)
        print('_________________________________________________')
        max = np.amax(list(values.values()))
        final_candidates = []
        for k in list(values.keys()):
            if values[k] == max:
                final_candidates += [k]
        action = random.choice(final_candidates)
        if action[0] == "scan":
            a = Action(action[1], 1.0)
        else:
            a = Action(action[1][0], 1.0, service=action[1][1], type="exploit")
        return a

    def reset(self):
        pass

    def __str__(self):
        pass

    def _process_state(self, s, update_knowledge=False):
        color_dict = {"network": "blue", "machine": "green", "hacker": "red", "vulnerability": "orange",
                      "adress": "yellow", 'compromission': 'pink'}
        color_dict_edge = {True: "green", False: "red", "Unknown": "blue"}
        g = Graph()
        adress_list = list(s._obs.keys())
        done = [False]
        g.add_vertex(name="H", classe="hacker")
        g.add_vertex(name="NH", classe="network")
        g.add_edge("H", "NH", belongs_to=True)
        g.add_vertex(name="C", classe="compromission")
        g.add_edge("H", "C", compromised=True)

        for i in range(len(s.service_indices)):
            g.add_vertex(name="V" + str(i), classe="vulnerability")
            # create a node for each vulnerability
        for adress in adress_list:
            id = adress_list.index(adress)
            network, _ = adress
            if done[network - 1] == False:
                g.add_vertex(name="N" + str(network), classe="network")
                done[network - 1] = True
                done += [False]
            g.add_vertex(name="M" + str(id), classe="machine")
            g.add_edge("M" + str(id), "N" + str(network), belongs_to=True)
            g.add_vertex(name=str(adress), classe="adress")
            g.add_edge("M" + str(id), str(adress), has_adress=True)
            # g.add_edge(str(adress),"M" + str(id), is_adress_of=True)

            if s._obs[adress]["compromised"]:
                g.add_edge("M" + str(id), "C", compromised=True)
            else:
                g.add_edge("M" + str(id), "C", compromised=False)

            for vuln in list(s._obs[adress].keys())[2:]:
                if s._obs[adress][vuln] == 0:
                    val = "Unknown"
                elif s._obs[adress][vuln] == 1:
                    val = True
                elif s._obs[adress][vuln] == 2:
                    val = False
                g.add_edge("M" + str(id), "V" + str(vuln), is_vuln=val)
            # recuperer topologie grace aux machines accessibles
            if update_knowledge:
                for m in s._obs:
                    if s._obs[m]["compromised"]:
                        serv, _ = m
                        self.topology_knowledge[serv] = self.true_topology[serv]
                        for a in range(len(self.topology_knowledge[serv])):
                            if self.topology_knowledge[serv][a] == 1:
                                self.topology_knowledge[a][serv] = 1
                            else:
                                self.topology_knowledge[a][serv] = 0

        # TODO repasser en non observable
        self.topology_knowledge = self.true_topology
        for i in range(len(self.topology_knowledge)):
            for j in range(i, len(self.topology_knowledge)):
                if self.topology_knowledge[i][j] == 0:
                    val = False
                elif self.topology_knowledge[i][j] == 1:
                    val = True
                elif self.topology_knowledge[i][j] == 2:
                    val = "Unknown"
                    # TODO change by Tribool
                if i == 0:
                    source = "NH"
                else:
                    source = "N" + str(i)
                if j == 0:
                    dest = "NH"
                else:
                    dest = "N" + str(j)
                g.add_edge(source, dest, connected=val)
        for v in g.vs:
            v["color"] = color_dict[v["classe"]]
            v["label"] = v["name"]
        for e in g.es:
            for att in e.attributes():
                if e.attributes()[att] is not None and att != "label" and att != "color" and att != 'name':
                    e["name"] = att
                    e["color"] = color_dict_edge[e.attributes()[att]]
        # layout = g.layout_kamada_kawai()
        # plot(g, layout=layout, margin=20, vertex_label_dist=1)
        # show(g)
        return g

    def _choose_greedy_action(self, state, action_space, epsilon=0.05):
        return action_space.index(self.policy(state))

    def addExperience(self, s, a, new_s, visualize=False):
        print("Adding experience for action", a)
        knowledgeUpdated = False
        if equals(s, new_s):
            # Si pas de changement dans l'etat: s est une condition d'echec pour a
            print('No effects: adding to failure\n')
            knowledgeUpdated = self.addFailure(deepcopy(s), a, visualize=visualize)
        else:
            # Recuperer tous les effets potentiels qui transforment s en new_s
            potentialEffects = potentialEffect(s, new_s, get_parameters(a))
            integrated = False
            for e in potentialEffects:
                found = False
                for pred in self.knowledge['pred'][a.type]:
                    if pred.effect == e:
                        found = True
                        print("Effect", e, " already exists")
                        # Si l'effet est deja connu, on essaie de mettre a jour le modele
                        if not matches(s, pred, a):
                            integrated = pred.updateModel(s, a, self,visualize=visualize)
                            knowledgeUpdated = integrated
                        else:
                            # Si la situation est deja prise en compte pour cet effet, passer a l'effet suivant
                            print('Situation is already known, not updating')
                            integrated = True
                            break
                if found == False:
                    # si l'effet n'est pas connu, creer une prediction
                    params = get_parameters(a)
                    for i in range(len(params)):
                        params[i] = s.vs.select(name=params[i])[0].index
                    print("New effect. Creating a prediction for\n", e, ":")
                    self.knowledge['pred'][a.type] += [Prediction(deepcopy(s), e, params)]
                    knowledgeUpdated = True
                elif integrated == False:
                    # Si l'effet est connu mais le model n'a pas pu etre mis a jour,
                    # il s'agit d'un nouveau cas: on cree une prediction
                    print("Impossible to update model: adding a prediction")
                    params = get_parameters(a)
                    for i in range(len(params)):
                        params[i] = s.vs.select(name=params[i])[0].index
                    self.knowledge['pred'][a.type] += [Prediction(deepcopy(s), e, params)]
                    knowledgeUpdated = True
        return knowledgeUpdated
        # TODO gerer overlapping models
        # TODO gerer nombre predictions differentes

    def updateValues(self, current_s, env):
        actions = []
        new_V = defaultdict(lambda: self.new_state_value)
        # On commence par considerer toutes les actions possibles
        for a, _ in self.action_space:
            for add in self.adress_space:
                for v in range(self.nService):
                    if a == 'exploit':
                        action = Action(add, 1, type="exploit", service=v + 1)
                    else:
                        action = Action(add, 1)
                    actions += [action]
        current_s_rebuilt = rebuild_state(current_s, self)
        # Si l'etat courant n'est pas inclu dans la table des valeurs, le creer
        if current_s_rebuilt not in self.V.keys():
            self.V[current_s_rebuilt] = 0
        for k in self.V.keys():
            if k != self.keySMAX and not env._is_goal_state(k):
                correspondingState = self._process_state(k)
                candidates = []
                for a in actions:
                    # On predit l'effet de toutes les actions
                    predicted = self.predictTransition(correspondingState, a)
                    if predicted != SMAX:
                        next_state = rebuild_state(predicted, self)
                    else:
                        next_state = self.keySMAX
                    if next_state in self.V.keys():
                        # Si on a une valeur pour le prochain etat:
                        candidates += [self.getReward(correspondingState, a) + self.gamma * self.V[next_state]]
                    else:
                        # sinon, la considerer nulle
                        candidates += [self.getReward(correspondingState, a)]
                new_V[k] = np.amax(candidates)
                new_V[self.keySMAX] = 1000
        self.V = new_V

    def predictTransition(self, s, a):
        for failure in self.knowledge["failure"][a.type]:
            if matches(s, failure, a):
                # Si une des conditions d'echec est compatible avec l'etat courant
                # et l'action envisagée, il n'y aura pas d'effet
                return s
        E = []
        for pred in self.knowledge["pred"][a.type]:
            # sinon, Parcourir les predictions, et ajouter les effets dont le modele
            # est compatible avec la situation courante
            if matches(s, pred, a):
                E += [pred.effect]
        if E == []:
            # Si aucun effet, et la situation n'est pas une condition
            # d'echec, il faut experimenter. Donc on retourne SMAX pour favoriser l'exploration
            return SMAX
        for ei in E:
            for ej in E:
                if ej == ei:
                    continue
                elif incompatible(s, a, ei, ej):
                    # Si deux effets sont incompatible, il faut experimenter pour
                    # eliminer l'effet erroné
                    return SMAX
        # on applique la liste d'effet pour predire l'etat apres l'action
        s_next = apply(s, a, E)
        return s_next

    def addFailure(self, s, a, visualize=False):
        for failure in self.knowledge['failure'][a.type]:
            if matches(s, failure, a):  # or equals(s, failure.model):
                # si les representations d'echecs comporte deja un model compatible avec l'etat, rien a faire
                return False
        for failure in self.knowledge['failure'][a.type]:
            if failure.updateModel(s, a,self, visualize=visualize):
                # sinon essayer d'update une representation
                print('Model updated')
                return True
        # si aucune des representation n'a pu etre mise a jour, il s'agit d'un nouveau cas
        # Il faut creer une nouvelle prediction
        params = get_parameters(a)
        for i in range(len(params)):
            params[i] = s.vs.select(name=params[i])[0].index
        print("Adding a new failure condition")
        self.knowledge['failure'][a.type] += [Prediction(s, None, params)]

    def getReward(self, s, a):
        type = a.type
        serv = a.service
        addr = a.target
        reach = reachable(self, s, addr)
        addr = str(addr)
        targetMachine = s.vs[s.es[s.incident(addr, mode=ALL)[0]].source]
        if type == "scan":
            if reach:
                for e in s.incident(targetMachine, mode=ALL):
                    if s.es[e].attributes()['is_vuln'] == True or s.es[e].attributes()['is_vuln'] == False:
                        return 0 - a.cost
            return 0 - a.cost
        else:
            for e in s.incident(targetMachine, mode=ALL):
                if s.es[e].attributes()['compromised'] == True:
                    return 0 - a.cost
            vulNode = s.vs.select(name_eq="V" + str(serv - 1)).indices[0]
            if s.es[s.es.select(_between=(set([targetMachine.index]), set([vulNode]))).indices[0]].attributes()[
                'is_vuln'] == True:
                return 10 - a.cost
            else:
                return - a.cost

    def showKnowledge(self):
        for pred in self.knowledge['failure']:
            pred.model.vs[pred.parameter]['color'] = 'green'
            show(pred.model)
        for pred in self.knowledge['pred']:
            pred.model.vs[pred.parameter]['color'] = 'green'
            show(pred.model)
            show(pred.effect.oSrc)
            show(pred.effect.oDest)
            print(pred.effect)
