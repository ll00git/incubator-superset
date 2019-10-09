from __future__ import absolute_import

from flask_appbuilder.security.views import AuthDBView
from flask import current_app, request, redirect, flash, url_for, g
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.forms import LoginForm_db
from flask_appbuilder import expose
from flask_login import login_user

class AuthDBViewRedirect(AuthDBView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        intent = request.args.get('next','')
        current_app.logger.info("AuthDBViewRedirect_intent={}".format(intent))
        # user already logged in
        if g.user is not None and g.user.is_authenticated:
            if len(intent) > 0:
                return redirect(intent)
            return redirect(self.appbuilder.get_url_for_index)
        form = LoginForm_db()
        if form.validate_on_submit():
            user = self.appbuilder.sm.auth_user_db(form.username.data, form.password.data)
            # user invalid login
            if not user:
                flash(as_unicode(self.invalid_login_message), 'warning')
                redirect_url = self.appbuilder.get_url_for_login
                if len(intent) > 0:
                    redirect_url = url_for(self.appbuilder.sm.auth_view.__class__.__name__ + ".login", next=intent)
                current_app.logger.info("login=failed, retrial_url={}".format(redirect_url))
                return redirect(redirect_url)
            # user valid login
            login_user(user, remember=False)
            if len(intent) > 0:
                return redirect(intent)
            return redirect(self.appbuilder.get_url_for_index)
        return self.render_template(self.login_template,
                                    title=self.title,
                                    form=form,
                                    appbuilder=self.appbuilder)


class AuthLDAPViewRedirect(AuthDBView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        intent = request.args.get('next','')
        current_app.logger.info("AuthLDAPViewRedirect_intent={}".format(intent))
        # user already logged in
        if g.user is not None and g.user.is_authenticated:
            if len(intent) > 0:
                return redirect(intent)
            return redirect(self.appbuilder.get_url_for_index)
        form = LoginForm_db()
        if form.validate_on_submit():
            user = self.appbuilder.sm.auth_user_ldap(form.username.data, form.password.data)
            # user invalid login
            if not user:
                flash(as_unicode(self.invalid_login_message), 'warning')
                redirect_url = self.appbuilder.get_url_for_login
                if len(intent) > 0:
                    redirect_url = url_for(self.appbuilder.sm.auth_view.__class__.__name__ + ".login", next=intent)
                current_app.logger.info("login=failed, retrial_url={}".format(redirect_url))
                return redirect(redirect_url)
            # user valid login
            login_user(user, remember=False)
            if len(intent) > 0:
                return redirect(intent)
            return redirect(self.appbuilder.get_url_for_index)
        return self.render_template(self.login_template,
                                    title=self.title,
                                    form=form,
                                    appbuilder=self.appbuilder)
