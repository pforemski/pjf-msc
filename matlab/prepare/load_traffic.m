% Read given TXT dump file and convert to MAT file with KISS info
function PKT = load_traffic(dump_filename)

txt_filename = sprintf('%s.txt', dump_filename);
mat_filename = sprintf('%s.mat', txt_filename);

if ~exist(txt_filename, 'file')
    error('file does not exist: %s', txt_filename);
end

if ~exist(mat_filename, 'file')
    pkts = dlmread(txt_filename);
    PKT = pktinfo(pkts, 4, 12, 80);
    save(mat_filename, 'PKT');
else
    load(mat_filename);
end
