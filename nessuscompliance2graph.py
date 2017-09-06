#This takes as input a .nessus compliance scan file and outputs a graphic horizontal bar chart
#with PASSED, WARNING and FAILED 's.
#
#autor: @Ar0xA / ar0xa@tldr.nu

from bs4 import BeautifulSoup

# we dont use X - Sever hack
import matplotlib as mpl
mpl.use('Agg')

#set pyplot defaults, dont know why but it works
import matplotlib.pyplot as plt;
plt.rcdefaults()

import numpy as np
import argparse
import sys

#make a horizontal barchart from compliance_result into export_file. the args_format is the fileformat of export_file
def make_hbarchart(compliance_result,export_file,args_format):
    all_servers = []
    # x items do not change through this
    for result in compliance_result:
        all_servers.append(result[0])

    passed_data = []
    for result in compliance_result:
        passed_data.append(result[1])
    passed_data = np.array(passed_data) #needs to be array to use the correct positioning in ax.barh left=

    warning_data = []
    for result in compliance_result:
        warning_data.append(result[2])
    warning_data = np.array(warning_data)

    failed_data = []
    for result in compliance_result:
        failed_data.append(result[3])
    failed_data = np.array(failed_data)

    # now some magic to create the graph
    y_pos = np.arange(len(all_servers))
    fig = plt.figure(figsize = (10, 10), frameon = False)
    ax = fig.add_subplot(111)

    # TODO: emtpy bars dont need ax.text

    # passed data
    # create a green horizontal bar from the array passed_data for each host and add the number to it
    bar_passed = ax.barh(y_pos, passed_data, color = 'g')
    rects = bar_passed.patches
    for rect, label in zip(rects, passed_data):
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width() / 2 + 2, rect.get_y(), label, color = 'black', ha = 'center', va = 'bottom')

    # warning data
    # create a magenta horizontal bar from the array warning_data for each host and add the number to it
    bar_warning = ax.barh(y_pos, warning_data, color = 'm', left = passed_data)
    rects = bar_warning.patches
    for rect, label in zip(rects, warning_data):
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width() / 2, rect.get_y(), label, color = 'black', ha = 'center', va = 'bottom')

    # failed data
    # create a red horizontal bar from teh array failed_data for each host and add the number to it
    bar_failed = ax.barh(y_pos, failed_data, color = 'r', left = warning_data + passed_data)
    rects = bar_failed.patches
    for rect, label in zip(rects, failed_data):
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width() / 2, rect.get_y(), label, color = 'black', ha = 'center', va = 'bottom')

    # add info about the graph, and save it
    ax.set_title(export_file)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(all_servers)
    plt.savefig(export_file.replace(' ', '_') + '.'+ args_format)

#here we parse results from the nessus file, we extract the compliance results and return that in an array
#in the format [ ['hostname', int(passed), int(warning), int(failed)], [etc.] ]
def parse_results(hosts):
    tmp_res=[]
    # lets go through each host
    for host in hosts:
        failed = 0
        passed = 0
        warning = 0
        host_name = host['name']
        #lets iterate through the reportItem, here the compliance items will be
        reportItems = host.findAll('reportitem')
        for rItem in reportItems:
            #ok lets find all compliance result items, and ONLY compliance items
            try:
                compliance_item = rItem.find('cm:compliance-result')
                if (compliance_item != None) and(compliance_item.get_text() == 'PASSED'):
                    passed += 1
                elif(compliance_item != None) and(compliance_item.get_text() == 'FAILED'):
                    failed += 1
                elif(compliance_item != None) and(compliance_item.get_text() == 'WARNING'):
                    warning += 1
            except:
                print rItem
                sys.exit(1)
        print '%s has %i compliance passed, %i warnings and %i failed' % (host_name, passed, warning, failed)
        tmp_res.append([host_name, passed, warning, failed])
    return tmp_res

def main():
    parser = argparse.ArgumentParser(description = 'Create a graphic horizontal barchart from a Nessus compliance scan input file.')
    parser.add_argument('-i', '--input', help = 'Input file in .nessus format',
        default = None)
    parser.add_argument('-f', '--format', help = 'Export file format', choices = ['png', 'pdf', 'ps', 'eps', 'svg'],
        default = 'png')
    parser.add_argument('-n', '--name', help = 'Export file name. Default is Report name',
        default = None)
    args = parser.parse_args()

    if not args.input:
        print('Need input file. Specify one with -i')
        sys.exit(1)

    # read the file..might be big though...
    try:
        f = open(args.input, 'r')
    except:
        print 'File %s not found!' % args.input
        sys.exit(1)

    print 'Parsing file %s as xml into memory, hold on...' % (args.input)

    nessus_xml_data = BeautifulSoup(f.read(), 'lxml')

    # set the output filename
    if not args.name:
        repname = nessus_xml_data.report['name']
        if len(repname) > 0:
            export_file = repname
            print 'Valid policy found %s' % (export_file)
        else:
            print 'Didn\'t find any valid policyname in the file. Are yousure this is a valid nessus file?'
            sys.exit(1)
    else:
        export_file = args.name

    # see if there are any hosts that are reported on
    hosts = nessus_xml_data.findAll('reporthost')
    if len(hosts) == 0:
        print 'Didn\'t find any hosts in file. Is this a valid nessus file?'
        sys.exit(1)
    else:
        print 'Found %i hosts' % (len(hosts))

    compliance_result = []
    compliance_result = parse_results(hosts)

    print 'Magically making image %s' % (export_file.replace(' ', '_') + '.' + args.format)

    # ok now that we have the compliance results, lets make some magic!
    make_hbarchart(compliance_result,export_file, args.format)

if __name__ == "__main__":
  main()
