# tuleap-oauth-plugin
Authentication plugin using Tuleap Oauth2 App.
With this plugin:

 - User can be logged in Jenkins by using his Tuleap credentials.
 - Tuleap defined user groups can be used in the [Permission Matrix](https://plugins.jenkins.io/matrix-auth/)

In the matrix-based security administrator can make reference to:

 -  any valid Tuleap user
 -  any user group defined in any project with the syntax `Tuleap project short name#user group name` (example: `my_project#project_members`)

## Installation
You can either install the plugin via the [Jenkins Plugins Center](https://www.jenkins.io/doc/book/managing/plugins/#from-the-web-ui), or manually.
If you install the plugin manually you have to :
 - Clone the repository
 - In the repository directory: ``` mvn clean install ```
 - See https://www.jenkins.io/doc/book/managing/plugins/#advanced-installation
If you want to install via the Jenkins CLI see : https://www.jenkins.io/doc/book/managing/plugins/#advanced-installation

## Configuration

Go to the **Global security** menu. **Manage Jenkins** => **Configure Global Security** .
In **Security Realm** chose **Tuleap Authentication**.
Fill the form.

**Notes**:
 - The Tuleap URI must be an https URI.
 - The client ID and the Client secret can be found in your [Tuleap OAuth2 Application](https://docs.tuleap.org/user-guide/oauth2.html).


## Authentication
Click on the **log in** button.
If you are not logged in Tuleap then the Tuleap login will be displayed.
If you did not accept the application authorization then the page will be displayed and you have to click on **Authorize**
You should be redirected to your Jenkins instance root URL and you should be logged with the username used to be logged in Tuleap.
