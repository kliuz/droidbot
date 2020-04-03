#!/bin/bash

#droidbot -a WhatsApp.apk -o output -keep_app -is_emulator
droidbot -a WhatsApp.apk -o output -script scripts/send_msg.json -keep_app -is_emulator
