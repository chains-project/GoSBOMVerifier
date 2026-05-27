"""
To remove verbose logging remove all 'vprint' in files or set verbose to false at all times.
"""

VERBOSE = False

def vprint(*args, **kwargs):
    #Print only when verbose mode is enabled.
    if VERBOSE:
        print("[VERBOSE]", *args, **kwargs)
