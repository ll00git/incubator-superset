# pylint: disable=C,R,W
import functools
import logging

from flask import current_app, flash
from flask import redirect, request, url_for
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.const import (
    FLAMSG_ERR_SEC_ACCESS_DENIED, LOGMSG_ERR_SEC_ACCESS_DENIED, PERMISSION_PREFIX,
)


log = logging.getLogger(__name__)
logging.getLogger('MARKDOWN').setLevel(logging.INFO)


def has_access(f):
    """
        This function overwrites the has_access function in
        flask_appbuilder/security/decorators.py by adding
        parameter 'next' from request's arg to redirect after login.
    """
    if hasattr(f, '_permission_name'):
        permission_str = f._permission_name
    else:
        permission_str = f.__name__

    def wraps(self, *args, **kwargs):
        permission_str = PERMISSION_PREFIX + f._permission_name
        if self.appbuilder.sm.has_access(permission_str, self.__class__.__name__):
            return f(self, *args, **kwargs)
        else:
            log.warning(LOGMSG_ERR_SEC_ACCESS_DENIED.format(
                permission_str, self.__class__.__name__))
            flash(as_unicode(FLAMSG_ERR_SEC_ACCESS_DENIED), 'danger')
            redirect_next = request.args.get('next', request.path)
            if request.query_string and len(request.query_string) > 0:
                redirect_next += '?' + request.query_string
            current_app.logger.info('redirect_next={}'.format(redirect_next))
        return redirect(url_for(self.appbuilder.sm.auth_view.__class__.__name__ +
                                '.login', next=redirect_next))
    f._permission_name = permission_str
    return functools.update_wrapper(wraps, f)
