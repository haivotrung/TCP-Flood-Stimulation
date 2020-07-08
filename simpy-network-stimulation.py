import itertools
import random

import simpy
import statistics
import time
import csv


SERVER_SIZE = 100       # TCP Server size

HANDSHAKE_SEQUENCE_LENGTH = [1, 6]
ATTACKER_PACKETS_RANGE = [2,7]   
CONNECTION_LATANCY = 100      
T_INTER = [30, 300]        # Create a client every [min, max] seconds
SIM_TIME = 15000  # Simulation time in seconds


class Client:
    def __init__(self, IP, attacker_value):
        self.ip_address = IP
        self.attacker = attacker_value
        self.packets_sending = 1

    def isAttacker(self):
        return self.attacker
    
    def set_attacker_packets(self):
        if self.attacker == True:
            self.packets_sending = random.randint(*ATTACKER_PACKETS_RANGE)

class Server:
    def __init__(self, environment):
        self.processor = simpy.Resource(environment, SERVER_SIZE)
        self.avg_time = 0
        self.bad_time = 0
        self.finished_time = 0

        self.successful_connections = []
        self.unresolved_connections = []
        self.average_connection_times = []
        
        self.malicious_packets = []
        self.unresolved_nums = []
            
    
    def set_avg_time(self):
        self.avg_time = sum(self.average_connection_times) / \
            len(self.average_connection_times)
    
    def get_avg_time(self):
        return self.avg_time

    def set_bad_connections_time(self):
        if len(self.unresolved_connections) > 0:
            self.bad_time = sum(self.unresolved_connections) / len(self.unresolved_connections)
        else:
            self.bad_time = 0
    
    def get_bad_connections_time(self):
        return self.bad_time

    def set_finished_connections(self):
        if len(self.successful_connections) > 0:
            self.finished_time = sum(self.successful_connections) / len(self.successful_connections)
        else:
            self.finished_time = 0

    def get_finished_time(self):
        return self.finished_time


    def print_times_results(self):
        print("Average Connection time for ALL connections: %.1f" %
              (self.avg_time))

        print("Average Connection time for Attacker connections: %.1f" %
          (self.bad_time))

        print("Average Connection time for Client connections: %.1f" %
          (self.finished_time))

        print(self.unresolved_connections)
        print(self.successful_connections)
        print(self.average_connection_times)
        print(self.malicious_packets)
        print(self.unresolved_nums)

def handshake(environment, TCP_server, Client):
    start = environment.now

    # print('\n%s starting sending SYN at %.1f' % (Client.ip_address, start))

    if not (TCP_server.processor.count == SERVER_SIZE):
        if not (Client.isAttacker()):
            # timeout to send SYN/ACK packet
            req = TCP_server.processor.request()
            yield environment.timeout(0.5)


            # if Client sends back ACK packet, start transmission
            yield TCP_server.processor.release(req)

            # timeout for actual tranmission
            yield environment.timeout(random.randint(*HANDSHAKE_SEQUENCE_LENGTH))

            transmission_time = environment.now - start
            # print('%s finished communication in %.1f seconds.' %
            #       (Client.ip_address, transmission_time))
            
            # add transmission time into a global list
            updateTimes(transmission_time, False, TCP_server)
        else:
            Client.set_attacker_packets()
            TCP_server.malicious_packets.append(Client.packets_sending)

            #print('//Attacker sending %1d malicious SYN packets.' % (Client.packets_sending))
 
            while (Client.packets_sending > 0):
                TCP_server.processor.request()
                Client.packets_sending = Client.packets_sending - 1
                yield environment.timeout(0.5)
            
            # print('//No ACK received from %s.' % (Client.ip_address))
            
            # print(' Total number of unresolved request: %.1d. \n Capacity left: %.1d' % (
            #     TCP_server.processor.count, (TCP_server.processor.capacity - TCP_server.processor.count)))
 
            unresolved_req = TCP_server.processor.count

            TCP_server.unresolved_nums.append(unresolved_req)

            # add transmission time into a global list
            updateTimes(environment.now - start, True, TCP_server)
    else:
        #TCP_server.release(TCP_server.users.pop(0))
        print('**Server reached maximum, sending RST')

def updateTimes(time, is_attacker, TCP_server):
    if is_attacker == True:
        TCP_server.unresolved_connections.append(time)
        TCP_server.average_connection_times.append(time)
    else:
        TCP_server.successful_connections.append(time)
        TCP_server.average_connection_times.append(time)

    TCP_server.set_avg_time()
    TCP_server.set_bad_connections_time()
    TCP_server.set_finished_connections()



def client_generator(environment, TCP_server, time):
    """Generate new clients that arrive at the gas station."""
    for _ in itertools.count():
        yield environment.timeout(random.randint(*T_INTER))
        IP_generated = ".".join(map(str, (random.randint(0, 255)
                                               for _ in range(4))))
        
        environment.process(handshake(environment, TCP_server, Client(IP_generated, random.choice([True, False])
                                                      )))


def server_time_out(TCP_server, time_out_time):
    if len(TCP_server.processor.users) > 0:
        TCP_server.processor.release(TCP_server.processor.users.pop(0))
    
    time.sleep(time_out_time)

def methodOne():
    # Setup and start the simulation
    print('TCP Server')

    # Create environment and start processes
    TCP_server = Server(env)

    env.process(client_generator(env, TCP_server, 15000))

    # Execute!
    env.run(until=SIM_TIME)
    TCP_server.print_times_results()

def methodTwo():
    print('\nTCP Server - Average Backlog')
    TCP_server_2 = Server(env2)
    env2.process(client_generator(env2, TCP_server_2,
                                  TCP_server_2.get_avg_time()))

    # Execute!
    env2.run(until=SIM_TIME)
    TCP_server_2.print_times_results()


def methodThree():
    print('\nTCP Server - Unresolved Backlog')
    TCP_server_3 = Server(env3)
    env3.process(client_generator(env3, TCP_server_3,
                                  TCP_server_3.get_finished_time()))

    # Execute!
    env3.run(until=SIM_TIME)
    TCP_server_3.print_times_results()



env = simpy.Environment()
methodOne()

# env2 = simpy.Environment()
# methodTwo()

# env3 = simpy.Environment()
# methodThree()
