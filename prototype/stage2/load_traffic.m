% Read given TXT dump file and convert to MAT file with KISS info
function PKT = load_traffic(type, name, label)
KISSPATH = evalin('base', 'KISSPATH');

pcap_filename = sprintf('%s/../dumps/%s/%s', KISSPATH, type, name);
txt_filename = sprintf('%s/../dumps/%s/txt/%s.txt', KISSPATH, type, name);
mat_filename = sprintf('%s/../dumps/%s/mat/%s.mat', KISSPATH, type, name);

ds_dir = sprintf('%s/../datasets/%s/%d', KISSPATH, type, label);
ds_filename = sprintf('%s/%s.svm', ds_dir, name);

if ~exist(txt_filename, 'file')
    if ~exist(pcap_filename, 'file')
        error('Traffic dump not found: %s %s', type, name);
    else
        disp 'TXT file does not exist - parsing PCAP...';
        eval(sprintf('!stage1/pcap2txt/pcap2txt %s > %s 2>/dev/null', ...
            pcap_filename, txt_filename));
        
        if ~exist(txt_filename, 'file')
            error('Parsing did not produce output file');
        end
    end
end

if ~exist(mat_filename, 'file')
    disp 'MAT file does not exist - parsing TXT...';
    pkts = dlmread(txt_filename);
    PKT = pktinfo(pkts, 4, 12, 80, label);

    PKT.data = [];
    for fid = 1:size(PKT.flows, 2)
        flow = PKT.flows(fid);
        
        % 3 flow-level + 24 packet-level
        avgsize = [ PKT.flows(fid).windows.avgsize ];
        avgtimespace = [ PKT.flows(fid).windows.avgtimespace ];
        jitter = [ PKT.flows(fid).windows.jitter ];
        signatures = [flow.windows.signature];
        
        % normalize
        avgsize(avgsize > 1500) = 1500;
        avgsize = avgsize ./ 1500;
        
        avgtimespace(avgtimespace > 10000000) = 10000000;
        avgtimespace = avgtimespace ./ 10000000;
        
        jitter(jitter > 10000000) = 10000000;
        jitter = jitter ./ 10000000;
%         
%         signatures = signatures ./ (((PKT.G * PKT.C) - PKT.E)^2 / PKT.E);
%         
        % connect
        PKT.data = vertcat(PKT.data, [ ...
            avgsize' avgtimespace' jitter' ...
            reshape(signatures, PKT.G, size(PKT.flows(fid).windows, 2))' ...
        ]);
    end

    PKT.labels = ones(size(PKT.data, 1), 1) * label;
    save(mat_filename, 'PKT');
else
    load(mat_filename);
end

if ~exist(ds_filename, 'file')
    if ~exist(ds_dir, 'dir')
        fprintf('Creating new directory for label %d\n', label);
        eval(sprintf('!mkdir -p %s', ds_dir));
    end

    fprintf('SVM file does not exist - using MAT...\n');
	libsvmwrite(ds_filename, PKT.labels, sparse(PKT.data));
end
