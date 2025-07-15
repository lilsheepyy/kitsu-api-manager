# Thanks for using kitsu api manager, if you have any question, t.me/lilsheepyy

* **Special thanks to grayson for making such a cool css**
* **Special thanks to space for letting me rob half of his readme**

## **Starting:**

`sudo apt-get update -y && sudo apt-get upgrade -y`

`sudo apt-get install php sshpass dos2unix sqlite3 -y`

## **Database Setup:**

This project now uses a local sqlite3 database which is created
automatically on first run. You only need the `sqlite3` package
installed. The default location of the database file is defined in
`assets/config.json`.

Stop apache2 by doing:

`sudo service apache2 stop`

and also, inside the manager folder, do:

`chmod +x *`

## **Compile & Run:**

`go build`

`screen ./kitsumanager`

### Telegram Notifications (optional)

If you want to receive Telegram alerts when attacks are triggered, set the
`telegramBotToken` and `telegramChatID` fields in `assets/config.json`.
Leaving either of these blank will disable Telegram integration and the
application will still run normally.

### API Requests

Each method in `assets/config.json` can optionally include an `apis` array.
When an attack is triggered, the manager will send a GET request to every URL
listed in that array. Placeholders `{IP}`, `{PORT}`, `{DURATION}` and
`{METHOD}` will be replaced automatically.

## **Clearing logs:**

I also left a .sh file that will help you clear logs (for god sake do this every few days). It works with the sqlite3 database directly so no additional configuration is required.

 If it doesnt work or gives any errors, use dos2unix:

`dos2unix clearlogs.sh`

When you want to run it, please make sure you are not running the api manager, then you can run the sh file by doing:
`./clearlogs.sh`


## **Adding, Editing & Deleting Users:**

Go to the /login path, once there input the key (check the config.json and modify it), once logged in you can create, modify, delete and check current users.

To edit an user, just delete the existing one and make a new one with the changes, do not try to make a duped user
