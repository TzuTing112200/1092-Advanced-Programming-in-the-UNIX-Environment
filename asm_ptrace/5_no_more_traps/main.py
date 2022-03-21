outFile = open('temp.txt', 'w')
inFile = open('no_more_traps.asm', 'r')

for line in inFile:
    if 'cc' in line[line.find('\t'):32]:
        outFile.write(line)


inFile.close()
outFile.close()

















