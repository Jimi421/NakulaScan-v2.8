import importlib.util
import glob
import os


def load_plugins():
    plugins = []
    for path in glob.glob(os.path.join('plugins', '*.py')):
        name = os.path.splitext(os.path.basename(path))[0]
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, 'run'):
            plugins.append(module)
    return plugins
