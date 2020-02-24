import random
from collections import defaultdict

import numpy as np
from igraph import *

from network_attack_simulator.agents.agent import Agent
from network_attack_simulator.envs.action import Action

effect_types = ["arithmetic", "assignement", "discovery"]
SMAX = Graph(directed=True)

#g1s.get_subisomorphisms_vf2(g2s, node_compat_fn=compat_node, edge_compat_fn=compat_edges)


# class pickleDic(defaultdict):
#     def __getitem__(self, item):
#         super().__getitem__(item.write_pickle())
#
#     def __setitem__(self, key, value):
#         super().__setitem__(key.write_pickle(), value)
#
#     def keys(self):
#         keys = super()
#         temp = []
#         for k in keys:
#             temp += [Graph.Read_Pickle(k)]
#         return temp

def reachable(s,addr):
def compromised(s,addr):
def service_info(s,addr,serv):


class Prediction:
    def __init__(self, model, effect,parameter):
        self.model = model
        self.effect = effect
        self.parameter=parameter #tableau, adresse ou adresse,service
        self.readableParams=[self.model.vs[i]['name'] for i in parameter]
    def updateModel(self, s,a):
        candidates = s.get_subisomorphisms_vf2(self.model, node_compat_fn=compat_node,edge_compat_fn=(lambda q,w,e,r : True))
        params = get_parameters(a)
        temp = deepcopy(candidates)
        for c in temp:
            for i in range(len(params)):
                if s.vs[c[self.parameter[i]]]['name'] != params[i]:
                    candidates.remove(c)
        new=deepcopy(self.model)
        if len(candidates)>1:
            print("RHAAAAAAAAAAAAAAAAAAAAAA")
        c=candidates[0]
        to_delete=[]
        for edge in self.model.es:
            correspondingEdge=s.es[s.es.select(_between=(set([c[edge.source]]),set([c[edge.target]]))).indices[0]]
            for att in correspondingEdge.attributes():
                if edge[att]!=correspondingEdge[att]:
                    try:
                        to_delete+=[edge]
                        #new.delete_edges(edge.index)
                        break
                    except :
                        print('squalala')
        new.delete_edges(to_delete)
        #show(self.model)
        old_new_debug=deepcopy(new)
        #TODO Remove isolated
        clusters=new.components(mode=WEAK)
        for clust in clusters:
            if 0 in clust:
                new=new.subgraph(clust)
        if 'H' in new.vs[:]['name']:
            for e in new.es.select(connected=True, _from=0):
                if e.target != e.source:
                    show(new)
                    self.model=new
                    return
            #pas la meme cause:
        # self.model.get_isomorphism_vf2()
class Effect:
    def __init__(self, objectSource, objectDest, relation, effectList):  # relation,type,value):
        self.oSrc = objectSource
        self.oDest = objectDest
        self.relation = relation
        self.potentialTypes = []
        for type, val in effectList:
            self.potentialTypes += [(type, val)]
        # self.type=type
        # self.value=value

    def __eq__(self, other):

        return self.relation == other.relation and self.potentialTypes == other.potentialTypes

def multiIso(g1s,g2s):
    if len(g1s) != len(g2s):
        return False
    for i in range(len(g1s)):
        if not g1s[i].subisomorphic_vf2(g2s[i], node_compat_fn=compat_node, edge_compat_fn=compat_edges):
            return False
    return True
def show(g):
    if isinstance(g, Graph):
        for e in g.es:
            if e.attributes()['compromised']==True or e.attributes()['is_vuln']==True:
                e['color']='green'
        layout = g.layout_kamada_kawai()
        plot(g, layout=layout, margin=100, vertex_label_dist=1, edge_label_dist=2)
    elif isinstance(g, list):
        for graf in g:
            layout = graf.layout_kamada_kawai()
            plot(graf, layout=layout, margin=100, vertex_label_dist=1, edge_label_dist=2)


def showEffects(E):
    for e in E:
        show([e.oSrc] + [e.oDest])


def get_parameters(a):
    if a.type == 'scan':
        return [str(a.target)]
    elif a.type == 'exploit':
        return [str(a.target), 'V' + str(a.service)]


def equals(g1, g2):
    selfEdgeNode=[]
    for e in g2.es:
        if e.target==e.source:
            selfEdgeNode+=[e.target]
    corresp=g1.get_isomorphisms_vf2(g2, node_compat_fn=strong_compat_node, edge_compat_fn=strong_compat_edges)
    if corresp==[]:
        return False
    else:
        for c in corresp:
            for e in selfEdgeNode:
                for att in g2.es.attributes():
                    if g2.es[g2.es.select(_between=([c[e]],[c[e]])).indices[0]].attributes()[att]!=\
                        g1.es[g1.es.select(_between=([e],[e])).indices[0]].attributes()[att]:
                        return False
        return True





def strong_compat_node(g1, g2, n1, n2):
    node1 = g1.vs[n1]
    node2 = g2.vs[n2]
    try:
        for att in node1.attributes():
            if node1.attributes()[att] != node2.attributes()[att]:
                return False
    except:
        print("not the same attributes between ", node1, " and ", node2)
        return False
    return True


def strong_compat_edges(g1, g2, e1, e2):
    edge1 = g1.es[e1]
    edge2 = g2.es[e2]
    if e1==10 and e2==10:
        print("Same Node?? WTF??")
    try:
        for att in edge1.attributes():
            if edge1.attributes()[att] != edge2.attributes()[att]:
                return False
    except:
        print("not the same attributes between ", edge1, " and ", edge2)
        return False
    #print("Edge",edge1,"with attributes",[a for a in edge1.attributes() if edge1.attributes()[a]!=None],"matche edge",edge2,"with attributes",[a for a in edge2.attributes() if edge2.attributes()[a]!=None])
    return True


def compat_node(g1, g2, n1, n2):
    node1 = g1.vs[n1]
    node2 = g2.vs[n2]
    att1=node1.attributes()
    att2=node2.attributes()
    try:
        for att in node1.attributes():
            if not att in ['name', 'label']:
                if node1.attributes()[att] != node2.attributes()[att]:
                    return False
    except:
        print("not the same attributes between ", node1, " and ", node2)
        return False
    return True


def compat_edges(g1, g2, e1, e2):
    edge1 = g1.es[e1]
    edge2 = g2.es[e2]
    try:
        for att in edge1.attributes():
            if edge1.attributes()[att] != edge2.attributes()[att]:
                return False
    except:
        print("not the same attributes between ", edge1, " and ", edge2)
        return False
    return True


def findBestPath(s1, s2, e1, e2, parameter):
    # postulat: le meilleur moyen de referer a l'objet source et dest d'un arc
    # ayant changé de valeur est de prendre le chemin entre chacun des parametres et l'objet source/dest pour eviter l'ambiguité
    if len(parameter) == 1:
        path1 = s1.get_shortest_paths(e1.source, parameter, mode=ALL)  # link between action arg and source object
        path2 = [list(set(path1[0] + s1.get_shortest_paths(e1.source, e1.target, mode=ALL)[0]))]
    else:
        path1 = []
        path2 = []
        # trouver le noeud commun le plus proche
        parameterPath = s1.get_shortest_paths(parameter[0], parameter[1], mode=ALL)[0]
        if len(parameter) > 2 or len(parameterPath) != 3:
            print("dommage, bosse encore")
            exit(1)
        else:
            commonVertex = parameterPath[1]
            parameterPath = [s1.get_shortest_paths(commonVertex, parameter[0], mode=ALL)[0],
                             s1.get_shortest_paths(commonVertex, parameter[1], mode=ALL)[0]]
        for i in range(len(parameter)):
            path1 += [parameterPath[i] + s1.get_shortest_paths(e1.source, commonVertex, mode=ALL)[0]]
            # link between action arg and source object
            if e1.target in path1[i] and e1.target != e1.source:
                path2 += [deepcopy(path1[i])]
                path2[i].remove(e1.source)
            else:
                path2 += [list(set(path1[i] + s1.get_shortest_paths(e1.source, e1.target, mode=ALL)[0]))]
    # postulat: il existe une chaine de relation entre l'objet source/dest de la relation modifiee, et le parametre de l'action
    for i in range(len(path1)):
        path1[i] = s1.subgraph(path1[i])
        path2[i] = s1.subgraph(path2[i])
    return path1, path2


def potentialEffect(s1: object, s2: object, parameter):
    # get the elements different between s1 and s2
    diff_edge = []
    for e1 in s1.es:
        for e2 in s2.es:
            if s1.vs[e1.source].attributes() == s2.vs[e2.source].attributes() and s1.vs[e1.target].attributes() == \
                    s2.vs[
                        e2.target].attributes():  # compat_node(s1,s2,e1.source,e2.source) and compat_node(s1,s2,e1.target,e2.target):
                if not e1.attributes() == e2.attributes():  # compat_edges(s1,s2,e1.index,e2.index):
                    diff_edge += [(e1, e2)]
    consequence = []
    for e1, e2 in diff_edge:
        path1, path2 = findBestPath(s1, s2, e1, e2, parameter)
        # show(path1[i])
        # show(path2[i])
        att = e1.attributes()['label']
        old_value = e1.attributes()[att]
        new_value = e2.attributes()[att]
        if old_value != new_value:
            attEffect = att
            potentialTypes = []
            for t in effect_types:
                if t == 'discovery':
                    typeEffect = t
                    valEffet = None
                    potentialTypes += [(typeEffect, valEffet)]
                elif t == "assignement":
                    typeEffect = t
                    valEffet = new_value
                    potentialTypes += [(typeEffect, valEffet)]

                elif t == "arithmetic" and type(old_value) == type(new_value):
                    typeEffect = t
                    valEffet = new_value - old_value
                    potentialTypes += [(typeEffect, valEffet)]
        consequence += [Effect(path1, path2, attEffect, potentialTypes)]
    # postulat: Si une action a un effet sur la relation entre plusieurs couples d'objets,
    # et que les couples sont les memes classes, il s'agit du meme effet
    for effect1 in consequence:
        for effect2 in consequence:
            if effect1 is not effect2:
                if effect1 != effect2:
                    if multiIso(effect1.oSrc, effect2.oSrc) and multiIso(effect1.oDest,effect2.oDest):  # TODO replace by isomorphic
                        for potentialTypes1 in effect1.potentialTypes:
                            for potentialTypes2 in effect2.potentialTypes:
                                if potentialTypes1[0] == potentialTypes2[0] and potentialTypes1[1] != potentialTypes2[
                                    1]:  # si meme type et val diff
                                    effect1.potentialTypes.remove(potentialTypes1)
                                    consequence.remove(effect2)
                else:
                    consequence.remove(effect2)

    return consequence


'''
        for att in [e1.attributes()['label']]:#=att=e1.attributes()['label], normalement, un seul attribut actif
            old_value=e1.attributes()[att]
            new_value=e2.attributes()[att]
            if old_value!=new_value:
                attEffect=att
                for t in effect_types:
                    if t=='discovery':
                        typeEffect=t
                        valEffet=None
                        consequence += [Effect(path1, path2, attEffect, typeEffect, valEffet)]

                    elif t=="assignement":
                        typeEffect=t
                        valEffet=new_value
                        consequence += [Effect(path1, path2, attEffect, typeEffect, valEffet)]

                    elif t=="arithmetic" and type(old_value)==type(new_value):
                        typeEffect=t
                        valEffet=new_value-old_value
                        consequence+=[Effect(path1,path2,attEffect,typeEffect,valEffet)]
        '''


def get_refering_object(graph, subgraph, parameter):
    inter = []
    for sg in subgraph:
        corresp = graph.get_subisomorphisms_vf2(sg, node_compat_fn=compat_node, edge_compat_fn=compat_edges)
        simplified = sg.spanning_tree()
        ends = simplified.vs.select(_degree_lt=2)
        if len(ends) > 2:
            print('More than two nodes of degree 1, issue')
            exit(1)
        temp = []
        for candidate in corresp:
            if graph.vs[candidate[ends[0].index]].attributes()['name'] in parameter:
                temp += [candidate[ends[1].index]]  # return candidate[end[1].index]
            elif graph.vs[candidate[ends[1].index]].attributes()['name'] in parameter:
                temp += [candidate[ends[0].index]]  # return candidate[end[0].index]
        inter += [temp]
    if len(inter) < 2:
        return inter[0]
    else:
        final = set(inter[0]).intersection(*inter)
    return final


def apply(s, a, E):
    new_s = deepcopy(s)
    for effect in E:
        source, dest, rel, types, val = effect.oSrc, effect.oDest, effect.relation, effect.potentialTypes[0][0], \
                                        effect.potentialTypes[0][1]
        if a.type == 'scan':
            parameter = [str(a.target)]
        elif a.type == 'exploit':
            parameter = [str(a.target), 'V' + str(a.service)]

        SourceCandidates = get_refering_object(s, source, parameter)
        DestCandidates = get_refering_object(s, dest, parameter)
        edges = new_s.es.select(_between=(set(SourceCandidates), set(DestCandidates)))
        for e in edges:
            if types == 'assignement':
                e[rel] = val
                e['color']='green'
            elif types == 'discovery':
                e[rel] = True
                e['color']='green'
                # TODO CHANGE C'EST DEGEU
        return new_s

    # s_next=deepcopy(s)
    # for e in E:


def matches(situation, pred,a):
    candidates= situation.get_subisomorphisms_vf2(pred.model, node_compat_fn=compat_node, edge_compat_fn=compat_edges)
    params=get_parameters(a)
    temp=deepcopy(candidates)
    for c in temp:
        for i in range(len(params)):
            if situation.vs[c[pred.parameter[i]]]['name']!=params[i]:
                candidates.remove(c)
                break
    if len(candidates)>=1:
        return True
    elif len(candidates)==0:
        return False
    else:
        return True

def incompatible(s, a, ei, ej):
    if multiIso(ei.oSrc, ej.oSrc) and multiIso(ei.oDest, ej.oDest) and ei.relation== ej.relation:
        if apply(s, a, [ei]) != apply(s, a, [ej]):
            return True
    return False


class DoormaxAgent(Agent):

    def __init__(self, adress_space, nService, topology,
                 action_space=[("scan", ["adress"]), ("exploit", ["adress", "service"])], k=3, knowledge={}):
        self.lookUp = {}
        self.lookUp[str(SMAX.write_pickle())]=SMAX
        self.gamma = 0.9
        self.action_space = action_space
        self.adress_space = adress_space
        self.true_topology = topology
        self.nService = nService
        self.V = {}#defaultdict(lambda: 0)
        self.V[str(SMAX)]=0

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

    def test(self, env):
        ini_s = env._generate_initial_state()
        s = self._process_state(ini_s)
        test1=[Action((1, 0), 1),Action((1, 0), 1, service=0, type="exploit")]
        for a in test1:
            s,_,_=env.step(a)
        s=self._process_state(s)
        env2=deepcopy(env)
        a1=Action((2, 0), 1)
        a2=Action((2, 0), 1, service=0, type="exploit")
        a3=Action((3, 0), 1)
        a4=Action((3, 0), 1, service=0, type="exploit")
        s1,_,_=env.step(a1)
        s1=self._process_state(s1)
        s2, _, _ = env.step(a2)
        s2 = self._process_state(s2)
        s3,_,_=env.step(a3)
        s3=self._process_state(s3)
        s4,_,_=env.step(a4)
        s4=self._process_state(s4)
        equals(s3,s4)
        self.addExperience(s,a1,s1)
        self.addExperience(s1,a2,s2)
        self.addExperience(s2,a3,s3)
        self.addExperience(s3,a4,s4)
        #g_simple=Graph()
        #g.add_vertex(name=,label=)
        #print('here')

        # a = Action((3, 0), 1)
        # new_s, _, _ = env.step(a)
        # new_s = self._process_state(new_s)
        # self.addExperience(s, a, new_s)
        # s = new_s

    # apply(s,Action((1, 0),1),E)
    # s=new_s
    # new_s,_,_=env.step(Action((1,0), 1,service=0, type="exploit"))
    # new_s = self._process_state(new_s)
    # E=potentialEffect(s, new_s, ["(1, 0)","V0"])
    # apply(s, Action((1,0), 1,service=0, type="exploit"), E)

    def train(self, env, num_episodes=100, max_steps=100, timeout=None, verbose=False, **kwargs):
        self.test(env)
        # layout = g.layout_kamada_kawai()
        # plot(g, layout=layout, margin=10, vertex_label_dist=1,edge_label_dist=2)
        for episode in range(num_episodes):
            done = False
            step = 0
            ep_reward = 0
            max_steps = 100
            s = env._generate_initial_state()
            s = self._process_state(s)
            # new_s,_,_=env.step(Action((1, 0),1))
            # new_s = self._process_state(new_s)
            # E=potentialEffect(s,new_s,["(1, 0)"])
            # apply(s,Action((1, 0),1),E)
            # s=new_s
            # new_s,_,_=env.step(Action((1,0), 1,service=0, type="exploit"))
            # new_s = self._process_state(new_s)
            # E=potentialEffect(s, new_s, ["(1, 0)","V0"])
            # apply(s, Action((1,0), 1,service=0, type="exploit"), E)
            #self.updateValues(s)
            while not done:
                # s = self._process_state(s)
                #show(s)
                a = self.policy(s)  # policy(s)
                print(a)
                new_s, reward, done = env.step(a)
                new_s = self._process_state(new_s)
                self.addExperience(s, a, new_s)
                #self.showKnowledge()
                self.updateValues(new_s)
                if step == max_steps:
                    done = True
                step += 1
                ep_reward += reward
                s = new_s

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

    def policy(self, s):
        candidates = {}
        values = {}
        for a, classParam in self.action_space:
            candidates[a] = {}
            if a == "exploit":
                for addr in self.adress_space:
                    for serv in self.nService:
                        candidates[a][(addr, serv)] = self.predictTransition(s, Action(addr, 1.0, service=serv,
                                                                                       type="exploit"))
            elif a == "scan":
                for addr in self.adress_space:
                    candidates[a][addr] = self.predictTransition(s, Action(addr, 1.0))
            flatCandidates = {}
            for i in list(candidates.keys()):
                for j in list(candidates[i].keys()):
                    flatCandidates[(i, j)] = candidates[i][j]
            for k in flatCandidates.keys():
                if flatCandidates[k] == s:
                    values[k] = -1000
                elif flatCandidates[k] == SMAX:
                    values[k] = 1000
                else:

                    values[k] = self.V[str(s)]
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

    def _process_state(self, s):
        color_dict = {"network": "blue", "machine": "green", "hacker": "red", "vulnerability": "orange",
                      "adress": "yellow"}
        color_dict_edge = {True: "green", False: "red", "Unknown": "blue"}
        g = Graph(directed=True)
        adress_list = list(s._obs.keys())
        done = [False]
        g.add_vertex(name="H", classe="hacker")
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
                g.add_edge("M" + str(id), "M" + str(id), compromised=True)
            else:
                g.add_edge("M" + str(id), "M" + str(id), compromised=False)

            for vuln in list(s._obs[adress].keys())[2:]:
                if s._obs[adress][vuln] == 0:
                    val = "Unknown"
                elif s._obs[adress][vuln] == 1:
                    val = True
                elif s._obs[adress][vuln] == 2:
                    val = False
                g.add_edge("M" + str(id), "V" + str(vuln), is_vuln=val)
            # recuperer topologie grace aux machines accessibles
            for m in s._obs:
                if s._obs[m]["compromised"]:
                    serv, _ = m
                    self.topology_knowledge[serv] = self.true_topology[serv]
                    for a in range(len(self.topology_knowledge[serv])):
                        if self.topology_knowledge[serv][a] == 1:
                            self.topology_knowledge[a][serv] = 1
                        else:
                            self.topology_knowledge[a][serv] = 0
            '''
            if self.previous_reachable==[]:
                if s._obs[adress]["reachable"]:
                    #si premier etat, accessible=> exposed
                    self.topology_knowledge[0][network]=1
                    self.topology_knowledge[network][0]=1
                    self.previous_reachable+=[network]
                else:
                    self.topology_knowledge[0][network] = 0
                    self.topology_knowledge[network][0] = 0
            else:
                if self.last_compromised_net is not None:
                    if s._obs[adress]["reachable"] and network not in self.previous_reachable:
                        self.topology_knowledge[self.last_compromised_net][network] = 1
                        self.topology_knowledge[network][self.last_compromised_net] = 1                    self.previous_reachable+=[network]
                        self.previous_reachable+=[network]
                    elif not s._obs[adress]["reachable"]:
                        self.topology_knowledge[self.last_compromised_net][network] = 0
                        self.topology_knowledge[network][self.last_compromised_net] = 0
            '''

        for i in range(len(self.topology_knowledge)):
            for j in range(len(self.topology_knowledge)):
                if self.topology_knowledge[i][j] == 0:
                    val = False
                elif self.topology_knowledge[i][j] == 1:
                    val = True
                elif self.topology_knowledge[i][j] == 2:
                    val = "Unknown"
                    # TODO change by Tribool
                if i == 0:
                    source = "H"
                else:
                    source = "N" + str(i)
                if j == 0:
                    dest = "H"
                else:
                    dest = "N" + str(j)
                g.add_edge(source, dest, connected=val)
        for v in g.vs:
            v["color"] = color_dict[v["classe"]]
            v["label"] = v["name"]
        for e in g.es:
            for att in e.attributes():
                if e.attributes()[att] is not None and att != "label" and att != "color":
                    e["label"] = att
                    e["color"] = color_dict_edge[e.attributes()[att]]
        # layout = g.layout_kamada_kawai()
        # plot(g, layout=layout, margin=20, vertex_label_dist=1)
        return g

    def _choose_greedy_action(self, state, action_space, epsilon=0.05):
        pass

    def addExperience(self, s, a, new_s):
        if equals(s, new_s):
            # add s to failure for a
            self.addFailure(s, a)
        else:
            potentialEffects = potentialEffect(s, new_s, get_parameters(a))
            for e in potentialEffects:
                found = False
                for pred in self.knowledge['pred'][a.type]:
                    if pred.effect == e:
                        found = True
                        if pred.updateModel(s,a)==False:
                            self.knowledge['pred'][a.type] += [Prediction(s, e, params)]

                        '''
                        for c in pred[a][att][e.type]:
                            if c != p and matches(p.model, c.model):
                                #                                P.remove(pred[a][att][e.type])
                                P[a][att][e.type] = False
                        '''
                        # TODO gerer overlapping models
                if found == False:
                    for c in self.knowledge['pred'][a.type]:
                        if s.get_subisomorphisms_vf2(c.model, node_compat_fn=compat_node, edge_compat_fn=compat_edges):
                            # P[a][att][e.type] = False
                            print("issue")
                            # return pred,failure
                    params=get_parameters(a)
                    for i in range(len(params)):
                        params[i]=s.vs.select(name=params[i])[0].index
                    self.knowledge['pred'][a.type] += [Prediction(s, e,params)]
                    # if (len(pred[a][att][e.type])) > self.k:
                    # TODO gerer nombre predictions differentes
                    # P.remove(pred[a][att][e.type])
                    # P[a][att][e.type] = False

    def updateValues(self,current_s):
        actions = []
        new_V={}
        for a, _ in self.action_space:
            for add in self.adress_space:
                for v in range(self.nService):
                    if a == 'exploit':
                        action = Action(add, 1, type="exploit", service=v + 1)
                    else:
                        action = Action(add, 1)
                    actions += [action]
        temp=str(current_s.write_pickle())
#        for state in self.lookUp
        if not temp in self.V.keys():
            self.lookUp[temp]=current_s
            self.V[temp]=0
        for k in self.V.keys():
            if k!= str(SMAX):
                correspondingState=self.lookUp[k]
                candidates = []
                for a in actions:
                    predicted=self.predictTransition(correspondingState, a)
                    key=str(predicted.write_pickle())
                    #if key not in V.keys():
                    candidates += [self.getReward(correspondingState, a) + self.gamma * self.V[key]]
                new_V[k] = np.amax(candidates)
                new_V[str(SMAX)]=1000
        self.V=new_V
            # pour chaque etat connu different de SMAX
    def predictTransition(self, s, a):
        for failure in self.knowledge["failure"][a.type]:
            if matches(s, failure,a):
                return s
        E = []
        for pred in self.knowledge["pred"][a.type]:
            if matches(s, pred,a):
                E += [pred.effect]
        if E == []:
            return SMAX
        for ei in E:
            for ej in E:
                if ej == ei:
                    continue
                elif incompatible(s,a, ei, ej):
                    return SMAX
            # s_next = apply(s, E)
            # return s_next

        s_next = apply(s,a, E)
        return s_next

    def addFailure(self, s, a):
        for failure in self.knowledge['failure'][a.type]:
            if matches(s,failure,a):# or equals(s, failure.model):
                return
        params = get_parameters(a)
        for i in range(len(params)):
            params[i] = s.vs.select(name=params[i])[0].index
        self.knowledge['failure'][a.type] += [Prediction(s,None,params)]

    def getReward(self, s, a):
        type = a.type
        target_network, _ = a.target
        addr = str(a.target)
        serv = a.service
        reachable=False
        if self.true_topology[0][target_network] == 1:
            reachable = True
        compromised_edge = s.es.select(compromised_eq=True)
        compromised = [s.vs[x.target] for x in compromised_edge]
        targetMachine = s.vs[s.es[s.incident(addr, mode=ALL)[0]].source]
        for m in compromised:
            net = m.attributes()['name'].split(',')[0].split('(')[1]
            if self.true_topology[net][target_network] == 1:
                reachable = True
        if type == "scan":
            if reachable:
                for e in s.incident(targetMachine, mode=ALL):
                    if s.es[e].attributes()['is_vuln'] == True or s.es[e].attributes()['is_vuln'] == False:
                        return 0 - a.cost
            return 0- a.cost
        else:
            for e in s.incident(targetMachine, mode=ALL):
                if s.es[e].attributes()['compromised'] == True:
                    return 0 - a.cost
            vulNode = s.vs.select(name_eq="V" + str(serv - 1)).indices[0]
            if s.es[s.es.select(_between=(set([targetMachine.index]), set([vulNode]))).indices[0]].attributes()['is_vuln'] == True:
                return 10 - a.cost
            else:
                return - a.cost
    def showKnowledge(self):
        for pred in self.knowledge['failure']:
            pred.model.vs[pred.parameter]['color']='green'
            show(pred.model)
        for pred in self.knowledge['pred']:
            pred.model.vs[pred.parameter]['color']='green'
            show(pred.model)
            show(pred.effect.oSrc)
            show(pred.effect.oDest)
            print(pred.effect)
