# tuleap-oauth-plugin

> **NOTE** : This plugin is only relevant for **[Tuleap Entreprise](https://docs.tuleap.org/user-guide/tuleap-entreprise.html#tuleap-enterprise)** users.

This Jenkins plugin is a community effort.

Authentication plugin using [Tuleap Oauth2 App](https://docs.tuleap.org/user-guide/oauth2.html#oauth2-and-openidconnect).
With this plugin:

 - User can be logged in Jenkins by using his Tuleap credentials.
 - Tuleap defined user groups can be used in the [Permission Matrix](https://plugins.jenkins.io/matrix-auth/)

In the matrix-based security administrator can make reference to:

 -  any valid Tuleap user
 -  any user group defined in any project with the syntax `Tuleap project short name#user group name` (example: `my_project#project_members`)

Please find the documentation at [https://docs.tuleap.org/user-guide/ci.html](https://docs.tuleap.org/user-guide/ci.html)

## Report issues

Issues must be reported in [Request tracker of the Tuleap project](https://tuleap.net/plugins/tracker/?report=1136) under the category "Jenkins Authentication plugin".

## Authors

* ROBINSON Clarck
* GOYOT Martin
