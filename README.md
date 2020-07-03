# tuleap-oauth-plugin

> **NOTE** : This plugin is only available for **[Tuleap Entreprise](https://docs.tuleap.org/user-guide/tuleap-entreprise.html#tuleap-enterprise)** users.

Authentication plugin using [Tuleap Oauth2 App](https://docs.tuleap.org/user-guide/oauth2.html#oauth2-and-openidconnect).
With this plugin:

 - User can be logged in Jenkins by using his Tuleap credentials.
 - Tuleap defined user groups can be used in the [Permission Matrix](https://plugins.jenkins.io/matrix-auth/)

In the matrix-based security administrator can make reference to:

 -  any valid Tuleap user
 -  any user group defined in any project with the syntax `Tuleap project short name#user group name` (example: `my_project#project_members`)

For more information about the integration between Tuleap and Jenkins see: https://docs.tuleap.org/user-guide/ci.html?plugins-configuration#continuous-integration

## Installation
You can either install the plugin via the [Jenkins Plugins Marketplace](https://www.jenkins.io/doc/book/managing/plugins/#from-the-web-ui), or manually.
If you install the plugin manually you have to :
 - Clone the repository
 - In the repository directory: ``` mvn clean install ```
 - See https://www.jenkins.io/doc/book/managing/plugins/#advanced-installation
If you want to install via the Jenkins CLI see : https://www.jenkins.io/doc/book/managing/plugins/#advanced-installation

## Configuration

The plugin global configuration can be found here: https://docs.tuleap.org/user-guide/ci.html?plugins-configuration#jenkins-configuration

> **NOTE** : This plugin and Tuleap Git Branch Source are two independents plugins, you do not need to install Git Branch Source if you just want to use Tuleap Authentication.

### Authentication

To configure the authentication, you can found the documentation here: https://docs.tuleap.org/user-guide/ci.html?plugins-configuration#authentication-configuration

### Authorization

To configure the authorization matrix, you can found the documentation here: https://docs.tuleap.org/user-guide/ci.html?plugins-configuration#authorization-configuration
