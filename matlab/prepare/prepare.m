% Read given TXT dump file and convert to MAT file with KISS info
function pktinfo_filename = prepare(dump_filename)

pktinfo_filename = sprintf('%s.mat', dump_filename);
pkts = dlmread(dump_filename);
PKT = pktinfo(pkts, 4, 12, 80); %#ok
save(pktinfo_filename, 'PKT');
