import random
import time
from collections import defaultdict

import numpy as np
from igraph import *
from collections import OrderedDict

from network_attack_simulator.agents.agent import Agent
from network_attack_simulator.envs.action import Action
from network_attack_simulator.envs.state import State
from network_attack_simulator.envs.environment import NetworkAttackSimulator
from network_attack_simulator.envs.generator import  generate_config

effect_types = ["assignement", "discovery"]
SMAX = Graph()

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


def compromised(s,addr):
    targetMachine = s.vs[s.es[s.incident(str(addr), mode=ALL)[0]].source]
    for e in s.incident(targetMachine, mode=ALL):
        if s.es[e].attributes()['compromised'] == True:
            return True
    return False

def service_info(s,addr,serv):
    targetMachine = s.vs[s.es[s.incident(str(addr), mode=ALL)[0]].source].index
    vuln=s.vs.select(name="V"+str(serv))[0]
    value=s.es.select(_between=([targetMachine],[vuln.index]))[0].attributes()['is_vuln']
    if value==True:
        return 1
    elif value==False:
        return 2
    elif value=="Unknown":
        return 0
    else:
        print('here')

def reachable(agent,s, addr):
    reachable = False
    target_network, _ =addr
    addr = str(addr)
    if agent.true_topology[0][target_network] == 1:
        reachable = True
    compromised_edge = s.es.select(compromised_eq=True)
    compromised = [s.vs[x.target] for x in compromised_edge]
    for m in compromised:
        for e in s.incident(m, mode=ALL):
            if s.es[e].attributes()['has_adress']==True:
                m_adress=s.vs[s.es[e].target]
        net = int(m_adress.attributes()['name'].split(',')[0].split('(')[1])
        if agent.true_topology[net][target_network] == 1:
            reachable = True
    return reachable
def rebuild_state(state,agent):
    obs = OrderedDict()
    if state==str(SMAX):
        for adress in agent.adress_space:
            machine_state = OrderedDict()
            machine_state['compromised'] = True
            machine_state['reachable'] = True
            for service in range(agent.nService):
                machine_state[service] = -1
            obs[adress] = machine_state
        state = State(obs)
        return state
    for adress in agent.adress_space:
        machine_state = OrderedDict()
        machine_state['compromised']=compromised(state,adress)
        machine_state['reachable']=reachable(agent,state,adress)
        for service in range(agent.nService):
            machine_state[service]=service_info(state,adress,service)
        obs[adress]=machine_state
    state = State(obs)
    return state
class Prediction:
    def __init__(self, model, effect,parameter):
        self.model = model
        self.effect = effect
        self.parameter=parameter #tableau: adresse ou adresse,service
        self.readableParams=[self.model.vs[i]['name'] for i in parameter]
    def updateModel(self, s,a,visualize=True):
        #TODO update parameter index when removing nodes
        candidates = s.get_subisomorphisms_vf2(self.model, node_compat_fn=compat_node,edge_compat_fn=(lambda q,w,e,r : True))
        #corr=X.get_sub(Y)
        #corr[i]=j :
        # i in Y
        # j in X
        params = get_parameters(a)
        temp = deepcopy(candidates)
        for c in temp:
            for i in range(len(params)):
                try:
                    #Garder uniquement les isomorphisme dont le noeud parametre utilisé pour le modele
                    # correspond au noeud parametre utilisé dans la nouvelle situation
                    if s.vs[c[self.parameter[i]]]['name'] != params[i]:
                        candidates.remove(c)
                        break
                except:
                    print("...")
        #print('Isomorphisms between situation and old model')
        #for c in candidates:
            #print('----------------------------')
            #for n in c:
                #print(s.vs[c.index(n)].attributes()['name'],"replaced by",s.vs[n].attributes()['name'])
        for c in candidates:
            new = deepcopy(self.model)
            to_delete=[]
            #print("=================================================\n\n")
            for edge in self.model.es:
                #Pour chaque arc, trouver l'arc correspondant
                correspondingEdge=s.es[s.es.select(_between=(set([c[edge.source]]),set([c[edge.target]]))).indices[0]]
                for att in correspondingEdge.attributes():
                    if edge[att]!=correspondingEdge[att]:
                        #print("Old value for relation",att," between",self.model.vs[edge.source].attributes()['name'],'and',self.model.vs[edge.target].attributes()['name'],':',edge[att])
                        #print("New value for corresponding edge between",s.vs[c[edge.source]].attributes()['name'],'and',s.vs[c[edge.target]].attributes()['name'],':',correspondingEdge[att],"\n")
                        to_delete+=[edge]
                        break
            if len(to_delete)>1:
                #si plus d'une difference, pas le bon candidat
                continue
            for i in new.vs.indices:
                #Pour la visualisation changer le nom des noeuds par les
                # deux noms des noeuds dans le modele et la situation
                # et marquer les arcs a supprimer en gras
                new.vs[i]['label'] += '(' + s.vs[c[i]].attributes()['label'] + ')'
            for e in to_delete:
                new.es[e.index]['width']=4
                new.es[e.index]['color']='black'
            show(new)

            new.delete_edges(to_delete)
            #show(self.model)
            clusters=new.components(mode=WEAK)
            #Recuperer les clusters pour essayer de supprimer les noeuds isolés.
            # Si un noeud est isolé, les relations avec celui ci n'importent pas, et il
            # n'influe pas dans l'issue d'une action
            for clust in clusters:
                #Un cluster est valide si H, et les parametres, sont inclus, et si sa taill
                wrongCluster=False
                parametersChanged=False
                namesClust=[new.vs[i].attributes()['name'] for i in clust]
                for p in self.readableParams+['H']:
                    if p not in namesClust:
                        wrongCluster=True
                if len(clust)<len(new.vs):
                    parametersChanged=True
                if not wrongCluster:
                    new=new.subgraph(clust)
                    if parametersChanged:
                        new_params=[]
                        #Actualiser l'indice du/des parametre.s, si on retire des noeuds
                        for p in self.readableParams:
                            try:
                                new_params+=[new.vs.select(name_eq=p).indices[0]]
                            except:
                                print('dsd')
                        break
            #Verifier que H est connecté au reste du reseau
            if not wrongCluster and 'H' in new.vs[:]['name']:
                for e in new.es.select(connected=True, _from=0):
                    if e.target != e.source:# si il ne s'agit pas de l'arc reliant H a lui-meme
                        if self.effect is None:
                            t='failure '+a.type+ str(a.target)
                        else:
                            t='pred' + a.type
                        if a.type=='exploit':
                            t+=str(a.service)
                        print('*********************Model Update for',t, '***************************')
                        for edge in to_delete:
                            att=edge.attributes()['name']
                            correspondingEdge = s.es[s.es.select(_between=(set([c[edge.source]]), set([c[edge.target]]))).indices[0]]
                            print("Old value for relation",att," between",self.model.vs[edge.source].attributes()['name'],'and',self.model.vs[edge.target].attributes()['name'],':',edge[att])
                            print("New value for corresponding edge between",s.vs[c[edge.source]].attributes()['name'],'and',s.vs[c[edge.target]].attributes()['name'],':',correspondingEdge[att],"\n")
                        show(self.model,visualize=visualize)
                        show(new,visualize=visualize)
                        self.model=new
                        if parametersChanged:
                            print('Old:',self.readableParams)
                            print('New:',[self.model.vs[i]['name'] for i in new_params])
                            self.parameter=new_params
                            self.readableParams = [self.model.vs[i]['name'] for i in self.parameter]
                        return True
        return False
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
    def __str__(self):
        return str(self.oSrc[0]).split('\n')[-1]+"\n"+str(self.oDest[0]).split('\n')[-1]+"\n"+self.relation+"\n"+str(self.potentialTypes)
    def __eq__(self, other):

        return multiIso(self.oSrc,other.oSrc) and multiIso(self.oDest,other.oDest) and self.relation == other.relation and self.potentialTypes == other.potentialTypes #TODO add multiIso

def multiIso(g1s,g2s):
    if len(g1s) != len(g2s):
        return False
    for i in range(len(g1s)):
        if not g1s[i].subisomorphic_vf2(g2s[i], node_compat_fn=compat_node, edge_compat_fn=compat_edges):
            return False
    return True
def show(g,visualize=False):
    if not visualize:
        return
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
            '''
            from igraph import Graph, Plot
from igraph.drawing.text import TextDrawer
import cairo

#plot = Plot("plot.png", bbox=(600, 650), background="white")
#plot.add(new, bbox=(20, 70, 580, 630))
#plot.redraw()
layout = new.layout_kamada_kawai()
drawing=plot(new, layout=layout, margin=100, vertex_label_dist=1, edge_label_dist=2)
ctx = cairo.Context(drawing.surface)
ctx.set_font_size(36)
drawer = TextDrawer(ctx, "Test title", halign=TextDrawer.CENTER)
drawer.draw_at(100, 100, width=600)
#drawing.redraw()
drawing.show()
            '''

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
    #if e1==10 and e2==10:
    #    print("Same Node?? WTF??")
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
    #att1=node1.attributes()
    #att2=node2.attributes()
    try:
        #for att in node1.attributes():
        #    if not att in ['name', 'label']:
        if node1.attributes()["classe"] != node2.attributes()["classe"]:
            return False
    except:
        print("not the same attributes between ", node1, " and ", node2)
        return False
    return True


def compat_edges(g1, g2, e1, e2):
    edge1 = g1.es[e1]
    edge2 = g2.es[e2]
    try:
        att=edge1.attributes()["name"]
#        for att in edge1.attributes():
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
        path1 = s1.get_shortest_paths(e1.target, parameter, mode=ALL)  # link between action arg and source object
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
                    s2.vs[e2.target].attributes():  # compat_node(s1,s2,e1.source,e2.source) and compat_node(s1,s2,e1.target,e2.target):
                if not e1.attributes() == e2.attributes():  # compat_edges(s1,s2,e1.index,e2.index):
                    diff_edge += [(e1, e2)]
    consequence = []
    for e1, e2 in diff_edge:
        path1, path2 = findBestPath(s1, s2, e1, e2, parameter)
        # show(path1[i])
        # show(path2[i])
        att = e1.attributes()['name']
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
        consequence += [Effect(path1, path2, attEffect, potentialTypes)]
    # postulat: Si une action a un effet sur la relation entre plusieurs couples d'objets,
    # et que les couples sont les memes classes, il s'agit du meme effet
    for effect1 in consequence:
        for effect2 in consequence:
            if effect1 is not effect2:
                if effect1 != effect2:
                    if multiIso(effect1.oSrc, effect2.oSrc) and multiIso(effect1.oDest,effect2.oDest):
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
            try:
                if situation.vs[c[pred.parameter[i]]]['name'] != params[i]:
                    candidates.remove(c)
                    break
            except:
                print("bordel")
                raise
    if len(candidates)>=1:
        return True
    elif len(candidates)==0:
        return False
    else:
        print("negative length, of course")
        exit(-1)
def incompatible(s, a, ei, ej):
    if multiIso(ei.oSrc, ej.oSrc) and multiIso(ei.oDest, ej.oDest) and ei.relation== ej.relation:
        if apply(s, a, [ei]) != apply(s, a, [ej]):
            return True
    return False


class DoormaxAgent(Agent):

    def __init__(self, adress_space, nService, topology,
                 action_space=[("scan", ["adress"]), ("exploit", ["adress", "service"])], k=3, knowledge={}):
        #self.lookUp = {}
        #self.lookUp[str(SMAX.write_pickle())]=SMAX
        self.gamma = 0.9
        self.action_space = action_space
        self.adress_space = adress_space
        self.true_topology = topology
        self.nService = nService
        self.V = defaultdict(lambda: 0)
        obs = OrderedDict()
        for adress in self.adress_space:
            machine_state = OrderedDict()
            machine_state['compromised'] = True
            machine_state['reachable'] = True
            for service in range(self.nService):
                machine_state[service] = -1
            obs[adress] = machine_state
        self.keySMAX = State(obs)
        self.V[self.keySMAX]=1000

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
                    temp.es[e.index]['width']=4
                    temp.es[e.index]['color']='blue'
                show(temp)

    def test(self, env):
        s0 = env._generate_initial_state()
        s0_processed=self._process_state(s0,update_knowledge=True)

        a1=Action((1, 0), 1)
        s1,_,_=env.step(a1)
        s1_processed=self._process_state(s1,update_knowledge=True)
        self.addExperience(s0_processed,a1,s1_processed)

        a2=Action((1, 0), 1, service=0, type="exploit")
        s2, _, _ = env.step(a2)
        s2_processed = self._process_state(s2,update_knowledge=True)
        self.addExperience(s1_processed,a2,s2_processed)

        a3=Action((2, 0), 1)
        s3,_,_=env.step(a3)
        s3_processed=self._process_state(s3,update_knowledge=True)
        self.addExperience(s2_processed,a3,s3_processed)

        a4=Action((2, 0), 1, service=0, type="exploit")
        s4, _, _ = env.step(a4)
        s4_processed = self._process_state(s4,update_knowledge=True)
        self.addExperience(s3_processed, a4, s4_processed)

        a5=Action((3, 0), 1)
        s5, _, _ = env.step(a5)
        s5_processed = self._process_state(s5,update_knowledge=True)
        self.addExperience(s4_processed, a5, s5_processed)

        a6=Action((3, 0), 1, service=0, type="exploit")
        s6,_,_=env.step(a6)
        s6_processed=self._process_state(s6,update_knowledge=True)
        self.addExperience(s5_processed,a6,s6_processed)
        print('here')

        self.reset_topology_knowledge()

        s0 =env.reset() #env._generate_initial_state()
        s0_processed = self._process_state(s0)
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
    def get_true_predictions(self):
        color_dict = {"network": "blue", "machine": "green", "hacker": "red", "vuln": "orange", "adress": "yellow"}
        modelGraphScanExposed=Graph()
        modelGraphScanExposed.add_vertex("H",classe="hacker")
        modelGraphScanExposed.add_vertex("N",classe="network")
        modelGraphScanExposed.add_vertex("M",classe="machine")
        modelGraphScanExposed.add_vertex("A",classe="adress")
        modelGraphScanExposed.add_vertex("V",classe="vuln")
        for v in modelGraphScanExposed.vs:
            v["color"] =color_dict[c]
        modelGraphScanExposed.add_edge("H","N",connected=True)
        modelGraphScanExposed.add_edge("N","M",belongs_to=True)
        modelGraphScanExposed.add_edge("A","M",has_adress=True)
        modelGraphScanExposed.add_edge("M","V",is_vuln="Unknown")

        modelGraphScan=Graph()
        modelGraphExploitExposed=Graph()
        modelGraphScanExposed.add_vertex("H",classe="hacker")
        modelGraphScanExposed.add_vertex("N",classe="network")
        modelGraphScanExposed.add_vertex("M",classe="machine")
        modelGraphScanExposed.add_vertex("A",classe="adress")
        modelGraphScanExposed.add_vertex("V",classe="vuln")
        for v in modelGraphScanExposed.vs:
            v["color"] =color_dict[c]
        modelGraphScanExposed.add_edge("H","N",connected=True)
        modelGraphScanExposed.add_edge("N","M",belongs_to=True)
        modelGraphScanExposed.add_edge("A","M",has_adress=True)
        modelGraphScanExposed.add_edge("M","V",is_vuln=True)

        modelGraphExploit=Graph()

    def train(self, env, num_episodes=100, max_steps=100, timeout=None, verbose=False, **kwargs):
        #self.test(env)
        knowledgeUpdated=True
        visualize=False
        if kwargs['knowledge'] is not None:
            self.knowledge=kwargs['knowledge']
        if kwargs['visualize'] is not None:
            visualize=kwargs['visualize']
        episodes_times=[]
        episodes_rewards=[]
        episode_steps=[]
        for episode in range(num_episodes):
            episode_start_time=time.time()
            if not knowledgeUpdated:
                break
            done = False
            step = 0
            ep_reward = 0
            max_steps = 100
            s = env.reset()
            self.reset_topology_knowledge()
            print("================================================")
            print("New episode")
            print("================================================")

            print(s)
            s = self._process_state(s)
            #show(s,visualize=True)
            while not done:
                print("------------------------------------------------------")
                print("New step")

                start = time.time()
                a = self.policy(s)  # policy(s)
                new_s, reward, done = env.step(a)
                new_s = self._process_state(new_s,update_knowledge=True)
                show(new_s)
                knowledgeUpdated=self.addExperience(s, a, new_s,visualize=visualize)
                #self.showKnowledge()
                self.updateValues(new_s,env)
                if step == max_steps:
                    done = True
                step += 1
                ep_reward += reward
                s = new_s
                if done ==True:
                    print("\n\n=============================================\n Episode ended\n=============================================")
                    print("Total reward:",ep_reward)
                    episode_time=time.time()-episode_start_time
                    episode_steps+=[step]
                    episodes_rewards+=[ep_reward]
                    episodes_times+=[episode_time]
                elapsed = time.time() - start
                print("Loop time:", elapsed)
        return episode_steps,episodes_rewards,episodes_times
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
        for t, classParam in self.action_space:
            candidates[t] = {}
            if t == "exploit":
                for addr in self.adress_space:
                    for serv in range(self.nService):
                        a=Action(addr, 1.0, service=serv,type="exploit")
                        candidates[t][(addr, serv)] = self.predictTransition(s, a)
            elif t == "scan":
                for addr in self.adress_space:
                    a=Action(addr, 1.0)
                    candidates[t][addr] = self.predictTransition(s, a)
        flatCandidates = {}
        for i in list(candidates.keys()):
            for j in list(candidates[i].keys()):
                flatCandidates[(i, j)] = candidates[i][j]
        for k in flatCandidates.keys():
            if equals(flatCandidates[k],s):
                values[k] = -1000
            elif flatCandidates[k] == SMAX:
                values[k] = 1000
            else:
                values[k] = self.V[rebuild_state(flatCandidates[k],self)]
        print('Values:')
        for k in values.items():
            print(k)
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

    def _process_state(self, s,update_knowledge=False):
        color_dict = {"network": "blue", "machine": "green", "hacker": "red", "vulnerability": "orange",
                      "adress": "yellow"}
        color_dict_edge = {True: "green", False: "red", "Unknown": "blue"}
        g = Graph()
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
        self.topology_knowledge=self.true_topology
        for i in range(len(self.topology_knowledge)):
            for j in range(i,len(self.topology_knowledge)):
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
                if e.attributes()[att] is not None and att != "label" and att != "color" and att != 'name':
                    e["name"] = att
                    e["color"] = color_dict_edge[e.attributes()[att]]
        # layout = g.layout_kamada_kawai()
        # plot(g, layout=layout, margin=20, vertex_label_dist=1)
        #show(g)
        return g

    def _choose_greedy_action(self, state, action_space, epsilon=0.05):
        return action_space.index(self.policy(state))

    def addExperience(self, s, a, new_s,visualize=False):
        print("Adding experience for action",a)
        knowledgeUpdated=False
        if equals(s, new_s):
            #Si pas de changement dans l'etat: s est une condition d'echec pour a
            print('No effects: adding to failure\n')
            knowledgeUpdated=self.addFailure(deepcopy(s), a,visualize=visualize)
        else:
            #Recuperer tous les effets potentiels qui transforment s en new_s
            potentialEffects = potentialEffect(s, new_s, get_parameters(a))
            integrated=False
            for e in potentialEffects:
                found = False
                for pred in self.knowledge['pred'][a.type]:
                    if pred.effect == e:
                        found = True
                        print("Effect",e," already exists")
                        #Si l'effet est deja connu, on essaie de mettre a jour le modele
                        if not matches(s,pred,a):
                            integrated=pred.updateModel(s, a,visualize=visualize)
                            knowledgeUpdated=integrated
                        else:
                            #Si la situation est deja prise en compte pour cet effet, passer a l'effet suivant
                            print('Situation is already known, not updating')
                            integrated=True
                            break
                if found == False:
                    #si l'effet n'est pas connu, creer une prediction
                    params=get_parameters(a)
                    for i in range(len(params)):
                        params[i]=s.vs.select(name=params[i])[0].index
                    print("New effect. Creating a prediction:\n")
                    print(e)
                    self.knowledge['pred'][a.type] += [Prediction(deepcopy(s), e,params)]
                    knowledgeUpdated=True
                elif integrated==False:
                    #Si l'effet est connu mais le model n'a pas pu etre mis a jour,
                    # il s'agit d'un nouveau cas: on cree une prediction
                    print("Impossible to update model: adding a prediction")
                    params = get_parameters(a)
                    for i in range(len(params)):
                        params[i] = s.vs.select(name=params[i])[0].index
                    self.knowledge['pred'][a.type] += [Prediction(deepcopy(s), e, params)]
                    knowledgeUpdated=True
        return knowledgeUpdated
                    # TODO gerer overlapping models
                    # TODO gerer nombre predictions differentes


    def updateValues(self,current_s,env):
        actions = []
        new_V=defaultdict(lambda: 0)
        #On commence par considerer toutes les actions possibles
        for a, _ in self.action_space:
            for add in self.adress_space:
                for v in range(self.nService):
                    if a == 'exploit':
                        action = Action(add, 1, type="exploit", service=v + 1)
                    else:
                        action = Action(add, 1)
                    actions += [action]
        current_s_rebuilt=rebuild_state(current_s, self)
        #Si l'etat courant n'est pas inclu dans la table des valeurs, le creer
        if current_s_rebuilt not in self.V.keys():
            self.V[current_s_rebuilt]=0
        for k in self.V.keys():
            if k!= self.keySMAX and not env._is_goal_state(k):
                correspondingState=self._process_state(k)
                candidates = []
                for a in actions:
                    #On predit l'effet de toutes les actions
                    predicted=self.predictTransition(correspondingState, a)
                    if predicted != SMAX:
                        next_state=rebuild_state(predicted,self)
                    else:
                        next_state=self.keySMAX
                    if next_state in self.V.keys():
                        #Si on a une valeur pour le prochain etat:
                        candidates += [self.getReward(correspondingState, a) + self.gamma * self.V[next_state]]
                    else:
                        #sinon, la considerer nulle
                        candidates += [self.getReward(correspondingState, a)]
                new_V[k] = np.amax(candidates)
                new_V[self.keySMAX]=1000
        self.V=new_V

    def predictTransition(self, s, a):
        for failure in self.knowledge["failure"][a.type]:
            if matches(s, failure,a):
                #Si une des conditions d'echec est compatible avec l'etat courant
                # et l'action envisagée, il n'y aura pas d'effet
                return s
        E = []
        for pred in self.knowledge["pred"][a.type]:
            #sinon, Parcourir les predictions, et ajouter les effets dont le modele
            # est compatible avec la situation courante
            if matches(s, pred,a):
                E += [pred.effect]
        if E == []:
            #Si aucun effet, et la situation n'est pas une condition
            # d'echec, il faut experimenter. Donc on retourne SMAX pour favoriser l'exploration
            return SMAX
        for ei in E:
            for ej in E:
                if ej == ei:
                    continue
                elif incompatible(s,a, ei, ej):
                    #Si deux effets sont incompatible, il faut experimenter pour
                    # eliminer l'effet erroné
                    return SMAX
        #on applique la liste d'effet pour predire l'etat apres l'action
        s_next = apply(s,a, E)
        return s_next

    def addFailure(self, s, a,visualize=False):
        for failure in self.knowledge['failure'][a.type]:
            if matches(s,failure,a):# or equals(s, failure.model):
                #si les representations d'echecs comporte deja un model compatible avec l'etat, rien a faire
                return False
        for failure in self.knowledge['failure'][a.type]:
            if failure.updateModel(s,a,visualize=visualize):
            #sinon essayer d'update une representation
                return True
        #si aucune des representation n'a pu etre mise a jour, il s'agit d'un nouveau cas
        #Il faut creer une nouvelle prediction
        params = get_parameters(a)
        for i in range(len(params)):
            params[i] = s.vs.select(name=params[i])[0].index
        self.knowledge['failure'][a.type] += [Prediction(s,None,params)]

    def getReward(self, s, a):
        type = a.type
        serv = a.service
        addr=a.target
        reach=reachable(self,s,addr)
        addr=str(addr)
        targetMachine = s.vs[s.es[s.incident(addr, mode=ALL)[0]].source]
        if type == "scan":
            if reach:
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
