
ACTION_ID2NAME = ['',
                  'Add a weak password for specific user.',
                  'Remove a password for specific user.',
                  'Remove all users.',
                  'Allow command execution and return output normally.',
                  'Block command execution and return permission issue string.',
                  'Block the access of the IP or port and allow command execution.',
                  'Redirect the access to another IP and allow command execution.',
                  'Replace specific string in the command and allow command execution.',
                  'Replace system-related string from the executed command.',
                  'Output the executed command normally with some version variation.',
                  'Show part of executed command only.',
                  'Stuff repeated and endless response to the attackers.',
                  'Intentionally leak some important information in the file and allow command execution.',
                  'Trigger the phishing email and stuff with fake data and allow command execution.',
                  'Reset system to the baseline.',
                  'Kill processes launched by the attacker and allow command execution.']

ACTION_LEN = len(ACTION_ID2NAME) - 1
