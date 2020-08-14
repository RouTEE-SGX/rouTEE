def createChannels(channelNumber, scriptName):

    f = open(scriptName, 'w')
    for i in range(channelNumber):
        print >> f, "j user " + str(i+1)



if __name__ == '__main__':
    command = input("which script do you want to make (1: createChannels): ")
    
    if command == 1:
        channelNumber = input("how many channels: ")
        scriptName = raw_input("script name: ")
        createChannels(channelNumber, scriptName)
    else:
        print("wrong command")
