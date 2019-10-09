import functools
import logging

from flask import current_app, flash, g, request, redirect, url_for
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.const import LOGMSG_ERR_SEC_ACCESS_DENIED, FLAMSG_ERR_SEC_ACCESS_DENIED, PERMISSION_PREFIX

log = logging.getLogger(__name__)

def has_access(f):
    """
        This function overwrites the has_access function in flask_appbuilder/security/decorators.py by
        adding parameter 'next' from request's arg to redirect after login.
    """
    if hasattr(f, '_permission_name'):
        permission_str = f._permission_name
    else:
        permission_str = f.__name__

    def wraps(self, *args, **kwargs):
        permission_str = PERMISSION_PREFIX + f._permission_name
        if self.appbuilder.sm.has_access(permission_str, self.__class__.__name__):
            # has access right (logged in and can access)
            return f(self, *args, **kwargs)
        else:
            # no access right (maybe no user logged in, or maybe logged in but can't access)
            user_id = g.user.get_id() if g.user else None
            if user_id is not None:
                # logged in, can't access
                log.warning(LOGMSG_ERR_SEC_ACCESS_DENIED.format(permission_str, self.__class__.__name__))
                flash(as_unicode(FLAMSG_ERR_SEC_ACCESS_DENIED), "danger")
                return redirect(self.appbuilder.get_url_for_index)
                # return redirect("/") # works the same as get for index
            else:
                # not logged in, redirect to login with next
                redirect_next = request.args.get('next', request.path)
                if request.query_string and len(request.query_string) > 0:
                    next_str = request.query_string.decode(encoding='UTF-8')
                    redirect_next += "?" + next_str
                current_app.logger.info("redirect_next={}".format(redirect_next))
        return redirect(url_for(self.appbuilder.sm.auth_view.__class__.__name__ + ".login", next=redirect_next))
    f._permission_name = permission_str
    return functools.update_wrapper(wraps, f)
