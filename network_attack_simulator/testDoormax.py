from network_attack_simulator.envs.environment import NetworkAttackSimulator
from network_attack_simulator.experiments.experiment_util import get_scenario
from network_attack_simulator.experiments.experiment_util import get_agent
from network_attack_simulator.experiments.experiment_util import is_valid_agent
from network_attack_simulator.agents.DoormaxAgent import *

import matplotlib.pyplot as plt
import numpy as np
import sys


def smooth_rewards(rewards):
    window = 100
    smoothed = []
    for i in range(1, len(rewards)):
        interval = min(i, window)
        avg_reward = np.average(rewards[i - interval: i])
        smoothed.append(avg_reward)
    return smoothed


def plot_results(timesteps, rewards, times, env):

    fontsize = 12

    fig = plt.figure(figsize=(11, 9))

    episodes = list(range(len(timesteps)))

    ax1 = fig.add_subplot(131)
    ax1.plot(episodes, np.cumsum(timesteps))
    ax1.set_xlabel("Episode", fontsize=fontsize)
    ax1.set_ylabel("Cumulative timesteps", fontsize=fontsize)

    ax2 = fig.add_subplot(132)
    smoothed_rewards = smooth_rewards(rewards)
    smoothed_episodes = list(range(1, len(smoothed_rewards)+1))
    ax2.plot(smoothed_episodes, smoothed_rewards)
    ax2.set_xlabel("Episode", fontsize=fontsize)
    ax2.set_ylabel("Averaged Episode Reward", fontsize=fontsize)

    ax3 = fig.add_subplot(133)
    env.render_network_graph(initial_state=True, ax=ax3, show=False)

    fig.subplots_adjust(top=0.9, left=0.07, right=0.95, bottom=0.1, wspace=0.3)
    plt.show()


def main():

    if len(sys.argv) != 4 and len(sys.argv) != 5:
        print("Usage: python demo_solving.py agent scenario generate [seed]")
        return 1

    agent_name = sys.argv[1]
    if not is_valid_agent(agent_name, verbose=True):
        return 1
    scenario_name = sys.argv[2]
    generate = bool(int(sys.argv[3]))
    if len(sys.argv) == 5:
        seed = int(sys.argv[4])
    else:
        seed = 1

    print("Displaying {} scenario".format(scenario_name))
    if generate:
        print("Generating network configuration")
        scenario = get_scenario(scenario_name)
        if scenario is None:
            return 1
        num_machines = scenario["machines"]
        num_services = scenario["services"]
        rve = scenario["restrictiveness"]
        num_episodes = scenario["episodes"]
        max_steps = scenario["steps"]
        timeout = scenario["timeout"]
        print("\tnumber of machines =", num_machines)
        print("\tnumber of services =", num_services)
        print("\tfirewall restrictiveness =", rve)
        env = NetworkAttackSimulator.from_params(num_machines, num_services, restrictiveness=rve,
                                                 seed=seed)
        agent_scenario = scenario_name
    else:
        print("Loading network configuration")
        num_episodes = 200
        max_steps = 500
        timeout = 120
        # env = CyberAttackSimulatorEnv.from_file(scenario_name)
        env = NetworkAttackSimulator.from_params(51, 6,
                                                 r_sensitive=10, r_user=10,
                                                 exploit_cost=1, scan_cost=1,
                                                 restrictiveness=3, exploit_probs=0.7,
                                                 seed=2)
        agent_scenario = "default"

    train_args = {}
    train_args["visualize_policy"] = num_episodes // 1
    train_args['knowledge']=None
    train_args['visualize']=False
    train_args['training']=True
    train_args['experience']=None


    #Tutoriel
    #input()
    start_train1=time.time()
    TutoEnv = NetworkAttackSimulator.from_params(1, 1, simple=True)
    TutoAgent= get_agent(agent_name, agent_scenario, TutoEnv)
    #show(TutoAgent._process_state(TutoEnv._generate_initial_state()),True)

    TutoAgent.train(TutoEnv, num_episodes, max_steps, timeout,
                verbose=True, **train_args)
    train_args['knowledge']=TutoAgent.knowledge
    train_args['experience']=TutoAgent.experience
    end_train_1=time.time()
    print(end_train_1-start_train1)
    #gen_episode = TutoAgent.generate_episode(TutoEnv, max_steps)
    #TutoEnv.render_episode(gen_episode)


    #TutoEnv = NetworkAttackSimulator.from_params(1, 2, simple=True)
    #TutoAgent= get_agent(agent_name, agent_scenario, TutoEnv)
    #TutoAgent.train(TutoEnv, num_episodes, max_steps, timeout,
    #                verbose=True, **train_args)
    train_args['knowledge']=TutoAgent.knowledge
    TutoEnv2 = NetworkAttackSimulator.from_params(2, 1, simple=True)
    TutoAgent2 = get_agent(agent_name, agent_scenario, TutoEnv2)
#    show(TutoAgent2._process_state(TutoEnv2._generate_initial_state()),True)
    start_train2=time.time()

    TutoAgent2.train(TutoEnv2, num_episodes, max_steps, timeout,
                    verbose=True, **train_args)
    end_train_2=time.time()
    print(end_train_2-start_train2)

    #gen_episode = TutoAgent2.generate_episode(TutoEnv2, max_steps)
    #TutoEnv2.render_episode(gen_episode)
    agent = get_agent(agent_name, agent_scenario, env)
    train_args['knowledge']=TutoAgent2.knowledge
    train_args['experience']=TutoAgent2.experience
    #TutoEnv3 = NetworkAttackSimulator.from_params(10, 1, simple=True)
    #TutoAgent3 = get_agent(agent_name, agent_scenario, TutoEnv2)
    #TutoAgent3.train(TutoEnv3, num_episodes, max_steps, timeout,
    #                verbose=True, **train_args)
    if agent is None:
        return 1

    print("Solving {} scenario using {} agent".format(scenario_name, agent_name))

    train_args['visualize']=False
    train_args['training']=False
    env._generate_initial_state()
    s = env.reset()
    agent.new_state_value=2000

    agent.knowledge=TutoAgent2.knowledge
    agent.experience=TutoAgent2.experience
    start=time.time()
    #show(agent._process_state(env._generate_initial_state()),True)
    gen_episode = agent.generate_episode(env, max_steps)
    end=time.time()
    print("scenario solved in ",end-start," secs")
    #env.render_episode(gen_episode)
    #plot_results(ep_tsteps, ep_rews, ep_times, env)
    #ep_tsteps, ep_rews, ep_times = agent.train(env, num_episodes, max_steps, timeout,
     #                                          verbose=True, **train_args)

    #plot_results(ep_tsteps, ep_rews, ep_times, env)


if __name__ == "__main__":
    main()
