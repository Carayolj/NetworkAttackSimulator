from igraph import *
from igraph.drawing.text import TextDrawer
import cairo
from collections import OrderedDict
from network_attack_simulator.envs.state import State
from network_attack_simulator.doormax.predictions import *
SMAX = Graph()
effect_types = ["assignement", "discovery"]


def multiIso(g1s,g2s):
    if len(g1s) != len(g2s):
        return False
    for i in range(len(g1s)):
        if not g1s[i].subisomorphic_vf2(g2s[i], node_compat_fn=compat_node, edge_compat_fn=compat_edges):
            return False
    return True

def show(g,visualize=False,title=None,x=0,y=600):
    if not visualize:
        return
    if isinstance(g, Graph):
        for e in g.es:
            if e.attributes()['compromised']==True or e.attributes()['is_vuln']==True:
                e['color']='green'
        layout = g.layout_kamada_kawai()
        drawing = plot(g, layout=layout, margin=100, vertex_label_dist=1, edge_label_dist=2,bbox=(1000,1000))
        ctx = cairo.Context(drawing.surface)
        ctx.set_font_size(36)
        drawer = TextDrawer(ctx, title, halign=TextDrawer.CENTER)
        drawer.draw_at(x, y, width=100)
        # drawing.redraw()
        drawing.show()
        #plot(g, layout=layout, margin=100, vertex_label_dist=1, edge_label_dist=2)
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
            if node1.attributes()["classe"] == 'hacker' and node2.attributes()["classe"]=='machine':
                for e in g2.incident(node2):
                    if g2.es[e].attributes()['name']=='compromised' and g2.es[e].attributes()['compromised']==True:
                        return True
            elif node2.attributes()["classe"] == 'hacker' and node1.attributes()["classe"]=='machine':
                for e in g1.incident(node1):
                    if g1.es[e].attributes()['name']=='compromised' and g1.es[e].attributes()['compromised']==True:
                        return True
            else:
                return False
    except:
        print("not the same attributes between ", node1, " and ", node2)
        raise
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
                print("probleme")
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
        return True
    compromised_edge = s.es.select(compromised_eq=True)
    compromised = [s.vs[x.source] for x in compromised_edge]
    for m in compromised:
        if m.attributes()['name'] in ['H','C']:
            continue
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
