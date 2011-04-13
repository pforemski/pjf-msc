function setup()
    fullpath = mfilename('fullpath');
    [f1, f2, f3, f4, match, f5] = regexp(fullpath, '(.*)/[^/]+$');
    dirpath = char(match{1,1});
    
    assignin('base', 'KISSPATH', dirpath);
    path(path, sprintf('%s/lib', dirpath));
    path(path, sprintf('%s/stage1', dirpath));
    path(path, sprintf('%s/stage2', dirpath));
end