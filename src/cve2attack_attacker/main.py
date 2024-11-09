#!/usr/bin/env python3

from time import sleep

from cve2attack import read_cve2attack
from attacker import Attacker
import training
from telenotify import send_text


# Run cve.py to get all SSH related CVEs.
# Run cve2attack.py to convert CVEs to MITRE ATT&CK techniques (only 31 techniques is available) and split dataset.
# This script runs attacks.


IS_INTERACTIVE = False
IS_TRAINING = training.IS_TRAINING
RUNTIME_CHT_STR = {True: '訓練', False: '測試'}[IS_TRAINING]
SPLIT_RUN = 0
COWRIE_IDLE_TIME = 60
COWRIE_IDLE_TIME_ADD = 5


if __name__ == '__main__':
    if IS_INTERACTIVE:
        print('Attacker is run in INTERACTIVE mode.')

        attacker = Attacker()

        while True:
            try:
                print('Try to login first ...')
                is_login = attacker.try_login()

                if is_login:
                    print('Try to login first ... Done')
                    print()

                    while True:
                        cmd = input('CMD> ')

                        if len(cmd) == 0:
                            print('End of commands.')
                            break

                        output, exit_code = attacker.execute_command(cmd, False)

                        print('Output> ', output)
                        print('Exit Code> ', exit_code)
                        print()

                else:
                    print('Try to login first ... Failed')

                choice = input('Start a new session? [y/N] ')

                if choice.strip().lower() == 'y':
                    pass
                else:
                    break

            except KeyboardInterrupt:
                print('User interrupted.')
                break

        del attacker

    else:
        if IS_TRAINING:
            print('Attacker is run in TRAINING mode.')
            attacks = read_cve2attack('output/ssh_cves_labeled_filtered_train.csv')
        else:
            print('Attacker is run in TESTING mode.')
            attacks = read_cve2attack('output/ssh_cves_labeled_filtered_test.csv')

        send_text(f'RL {RUNTIME_CHT_STR}已開始')

        for i, attack in enumerate(attacks):
            attacker = Attacker()
            attacker.do_attack(attack[0], attack[1], not IS_TRAINING)

            print()
            print(f'CVE {i + 1}/{len(attacks)} completed.')
            print()

            sleep(3)

            if SPLIT_RUN > 0 and (i + 1) % SPLIT_RUN == 0:
                send_text(f'RL {RUNTIME_CHT_STR}已進行 {i+1}/{len(attacks)} ({int((i+1) / len(attacks) * 100)}%)')

                if IS_INTERACTIVE:
                    print('Reached SPLIT RUN stop point. Please restart COWRIE manually.')
                    input('Press ENTER to continue ...')
                else:
                    # Should sleep for more than COWRIE_IDLE_TIME in runner to trigger cowrie restart.
                    print('Reached SPLIT RUN stop point. Try to trigger COWRIE restart ...')
                    sleep(COWRIE_IDLE_TIME + COWRIE_IDLE_TIME_ADD)
                    print('Reached SPLIT RUN stop point. Try to trigger COWRIE restart ... Done')

            del attacker

        send_text(f'RL {RUNTIME_CHT_STR}已完成')
