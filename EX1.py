from scapy.all import *
import numpy as np
import matplotlib.pyplot as plt
from scapy.layers.dot11 import Dot11, Dot11Elt

from graphviz import *
import networkx as nx

my_colors = 'rgbkymc'


class myGraph:
    def __init__(self, path,namefile):
        self.pcap_file = rdpcap(path+namefile+".cap")
        self.path = path
        self.namefile=namefile


# pkts = rdpcap("/home/mint/Desktop/Projects/two.cap")

    def export(Self,plt,filename,format):
        try:
            path = Self.path+filename
            wholePath = path + '.' + format
            plt.savefig(wholePath, format=format)

            print(format + " created!")

        except SyntaxError:
            print("due to some error, the file wasn't created")

############## mac adresses #####################################
    def display_by_MAC_addresses(self):
        mac_adresses = {}  # new dictionary
        for pkt in self.pcap_file:
            mac_adresses.update({pkt[Dot11].addr1: 0})
        for pkt in self.pcap_file:
            mac_adresses[pkt[Dot11].addr1] += 1

        # MA_list = list(mac_adresses)

        MA = []
        for ma in mac_adresses:
            if mac_adresses[ma] > 100:            # values start from
                MA.append(mac_adresses[ma])

        plt.bar(range(len(MA)), sorted(MA), align='center', color=my_colors)
        plt.xticks(range(len(MA)), sorted(mac_adresses))
        plt.rcParams.update({'font.size': 10})
        plt.xlabel('MAC Address')
        plt.ylabel('Count')
        plt.title('Mac adresses Graph')

        # Set tick colors:
        ax = plt.gca()
        ax.tick_params(axis='x', colors='blue')
        ax.tick_params(axis='y', colors='red')
        ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=90)

        # plt.legend()
        plttoexport=plt.gcf()
        plt.show()
        formatfile = raw_input('insert format of file for export graph:\n')
        nameoffile = raw_input('insert name for the file:\n')
        if formatfile in ['pdf', 'PDF', 'jpg', 'JPG', 'PNG', 'png']:
            self.export(plttoexport,nameoffile,formatfile)
############## /mac adresses #####################################

############## networks #########################################
    def display_by_networks(self):
        networks = {}

        for pkt in self.pcap_file:
            if pkt.haslayer(Dot11Elt):
                try:
                    networks.update({str((pkt[Dot11Elt].info).decode("utf-8")): 0})
                except:
                    ""

        for pkt in self.pcap_file:
            if pkt.haslayer(Dot11Elt):
                try:
                    networks[str((pkt[Dot11Elt].info).decode("utf-8"))] += 1
                except:
                    ""

        networks_list = []
        for network in networks:
            networks_list.append(networks[network])

        plt.bar(range(len(networks)), sorted(networks_list), align='center', color=my_colors)
        plt.xticks(range(len(networks)), sorted(networks.keys()))
        plt.rcParams.update({'font.size': 10})
        plt.xlabel('Network')
        plt.ylabel('Count')
        plt.title('Networks Graph')

        # Set tick colors:
        ax = plt.gca()
        ax.tick_params(axis='x', colors='blue')
        ax.tick_params(axis='y', colors='red')
        ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=90)

        # plt.legend()
        plttoexport = plt.gcf()
        plt.show()
        formatfile = raw_input('insert format of file for export graph:\n')
        nameoffile = raw_input('insert name for the file:\n')
        if formatfile in ['pdf', 'PDF', 'jpg', 'JPG', 'PNG', 'png']:
            self.export(plttoexport, nameoffile, formatfile)
############## /networks #########################################

############## protocols #########################################
    def display_protocol(self):
        for pkt in self.pcap_file:
            print(pkt.payload.payload.name)

        protocol_map = {}
        for pkt in self.pcap_file:
            protocol_map.update({pkt.payload.payload.name: 0})

        for pkt in self.pcap_file:
            protocol_map[pkt.payload.payload.name] += 1

        print(protocol_map)
        labels = protocol_map.keys()
        sizes = protocol_map.values()
        # colors = ['yellowgreen', 'gold', 'lightskyblue', 'lightcoral']
    # explode = (0, 0.1, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')
        plt.title('Protocols Graph')
        plt.pie(sizes, labels=labels,
        autopct='%1.1f%%', shadow=True, startangle=90)
# Set aspect ratio to be equal so that pie is drawn as a circle.
        plt.axis('equal')
# fig = plt.figure()
# ax = fig.gca()
        plttoexport = plt.gcf()
        plt.show()
        formatfile = raw_input('insert format of file for export graph:\n')
        nameoffile = raw_input('insert name for the file:\n')
        if formatfile in ['pdf', 'PDF', 'jpg', 'JPG', 'PNG', 'png']:
            self.export(plttoexport, nameoffile, formatfile)
############## /protocols #########################################

############## src + dest #######################################
    # def display_srcdest(self):
    #     src = {}
    #     dst = {}
    # # pkts.conversations()
    #     for pkt in self.pcap_file:
    #         if hasattr(pkt.payload, 'src') and hasattr(pkt.payload, 'dst'):
    #             src.update({pkt.payload.src: 0})
    #             dst.update({pkt.payload.dst: 0})
    #
    #     for pkt in self.pcap_file.res:
    #         if hasattr(pkt.payload, 'src') and hasattr(pkt.payload, 'dst'):
    #             src[pkt.payload.src] +=1
    #             dst[pkt.payload.dst] +=1
    #     sorted_src = []
    #     sorted_dst = []
    #     for k in sorted(src):
    #         sorted_src.append(src[k])
    #     for k in sorted(dst):
    #         sorted_dst.append(dst[k])
    #
    #     plt.bar(range(len(src)), sorted_src, align='center', label='source', color='green')
    #     plt.xticks(range(len(src)), sorted(src.keys()))
    #     plt.bar(range(len(dst)), sorted_dst, align='center', label='dest', color='red')
    #     plt.xticks(range(len(dst)), sorted(dst.keys()))
    #     plt.title('IP payload source & destination Graph')
    #
    #     ax = plt.gca()
    #     ax.tick_params(axis='x', colors='blue')
    #     ax.tick_params(axis='y', colors='red')
    #     ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=90)
    #     plt.legend()
    #     plt.show()

############## /src + dest #######################################

############## whole graph #######################################
    def display_graph(self):
        G = nx.Graph()
        edges_list = []

        for pkt in self.pcap_file:
            if hasattr(pkt.payload, 'src') and hasattr(pkt.payload, 'dst'):
                edges_list.append((pkt.payload.src, pkt.payload.dst))

        plt.title('IP Whole Graph')
        # print(pkt.payload.src + " | " + pkt.payload.dst)
        plt.rcParams.update({'font.size': 10})
        G.add_edges_from(edges_list)
        nx.draw(G, with_labels=True, node_color=my_colors)

        plttoexport = plt.gcf()
        plt.show()
        formatfile = raw_input('insert format of file for export graph:\n')
        nameoffile = raw_input('insert name for the file:\n')
        if formatfile in ['pdf', 'PDF', 'jpg', 'JPG', 'PNG', 'png']:
            self.export(plttoexport, nameoffile, formatfile)

############## /whole graph #######################################


############## end of class ##########################################################################################

def open_file():
    # filename = input('Enter file name: ')

    # need to insert 'Try&Catch'
    print "hii"
    path = raw_input('insert path folder:\n')
    filename = raw_input('insert file name:\n')
    path=path+'/'
    print path+filename+".cap"
    return myGraph(path,filename)



def main():
    pathFile = open_file()
    answer = raw_input('show MAC addresses graph: y/n \n')
    if answer in ['y','Y']:
        pathFile.display_by_MAC_addresses()
    answer = raw_input('show NETWORKS graph: y/n \n')
    if answer in ['y','Y']:
        pathFile.display_by_networks()
    answer = raw_input('show PROTOCOLS graph: y/n \n')
    if answer in ['y','Y']:
        pathFile.display_protocol()
    # pathFile.display_srcdest()
    answer = raw_input('show IP CONVERSATIONS graph: y/n \n')
    if answer in ['y','Y']:
        pathFile.display_graph()

# call main
if __name__ == '__main__':
    main()