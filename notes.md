1. Level 1
   - To show how an actual SQL-injection is performed, we have prepared a simple Webserver.
   - for the first Task, you may enter a username and password to view the account details.
   - For example we can log in as Max with the password "password" and view his information.
   - There is a user called admin here, whose  data we now want to access.
   - looking at the code, you can see that the user and password variables are directly inserted into the sql string.
   - Does anyone have an idea what values we can use to access admin's data without knowing their password?
   - So, in order of logging in as admin we have to set the username to admin and somehow manipulate the rest of the string that the comparison password = '{password}' does not rome the row from the slection.
   - the simplest way to do this would be to add a comment symbol at the end of the username. by using the string `admin' --`, we can make sql ignore the password comparison so that the username is the only checked paramter
   - Another way would be to fake an AND or OR statement in the username.
   - in level 1.2 as you can see, we have switched the password and user checks. now this is ot even a hurdle since we can make the entire sql statement unnecessary by putting an `a'OR username='admin` in the username.
   - the first part will fail for all users but the second one simply picks the admin account and returns it.
2. Level 2
   - f