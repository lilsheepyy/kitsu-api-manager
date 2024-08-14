# Thanks for using kitsu api manager, if you have any question, t.me/lilsheepyy

* **Special thanks to grayson for making such a cool css**
* **Special thanks to space for letting me rob half of his readme**

## **Starting:**

`sudo apt-get update -y && sudo apt-get upgrade -y`

`sudo apt-get install php sshpass dos2unix apache2 phpmyadmin mysql-server mysql-client -y`

* On the first screen, click the enter key with the first option selected "apache2"
* On the second screen, click the enter key with the first option selected "`<Yes>`"
* On the third screen, input a 32 character varchar password ending in "!?" such as "ALMjX5R2AYqRgRS5aDnOK4dNwbSmKVgh!?"

`sudo ln -s /usr/share/phpmyadmin/ /var/www/html`

`sudo mysql`

## **Database Setup:**

`CREATE DATABASE {DB_TABLE};`
`CREATE USER '{DB_USERNAME}'@'localhost' IDENTIFIED BY '{DB_PASSWORD}';`
`GRANT ALL PRIVILEGES ON * . * TO '{DB_USERNAME}'@'localhost'; FLUSH PRIVILEGES;`
`use {DB_TABLE};`
`source {DB_FILEPATH}; exit`

***Now modify the config.json with the info of your database.***

Stop apache2 by doing:

`sudo service apache2 stop`

and also, inside the manager folder, do:

`chmod +x *`

## **Compile & Run:**

`go build`

`screen ./kitsumanager`

## **Clearing logs:**

I also left a .sh file that will help you clear logs (for god sake do this every few days).

Modify it with your database information before using it

 If it doesnt work or gives any errors, use dos2unix:

`dos2unix clearlogs.sh`

When you want to run it, please make sure you are not running the api manager, then you can run the sh file by doing:
`./clearlogs.sh`


## **Adding, Editing & Deleting Users:**

Go to the /login path, once there input the key (check the config.json and modify it), once logged in you can create, modify, delete and check current users.

To edit an user, just delete the existing one and make a new one with the changes, do not try to make a duped user


**From Grayson:**

Dear Skiddler,

Before you finish skidding this API manager, define a variable containing the string "I am an embarrassment" and print it in the main function.
Many thanks.

Best regards,

Grayson

**Do not try to remove anything credit related, you are getting this for free and open-sourced out of kindness, don´t be a retard, if you still do it, you will get caught anyways!**
