import pkgutil
import importlib

__modules__ = []

__path__ = pkgutil.extend_path(__path__, __name__)

for importer, modname, ispkg in pkgutil.walk_packages(path=__path__, prefix=__name__+'.'):
    __modules__.append(modname)


def getScript(className):
    for m in __modules__:
        mod = importlib.import_module(m)
        if not hasattr(mod, className):
            continue
        klass = getattr(mod, className)
        if klass:
            return klass
