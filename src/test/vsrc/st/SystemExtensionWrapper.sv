module SystemExtensionWrapper #(
  parameter integer NR_CC = 1,
  parameter integer M_AXID_BITS = 12,
  parameter integer S_AXID_BITS = 12,
  parameter integer M_AXADDR_BITS = 48,
  parameter integer S_AXADDR_BITS = 48,
  parameter integer EXT_INTR_BITS = 256
)(
  output                       s_axi_cfg_aw_ready,
  input                        s_axi_cfg_aw_valid,
  input  [S_AXID_BITS - 1:0]   s_axi_cfg_aw_bits_id,
  input  [S_AXADDR_BITS - 1:0] s_axi_cfg_aw_bits_addr,
  input  [7:0]                 s_axi_cfg_aw_bits_len,
  input  [2:0]                 s_axi_cfg_aw_bits_size,
  input  [1:0]                 s_axi_cfg_aw_bits_burst,
  input                        s_axi_cfg_aw_bits_lock,
  input  [3:0]                 s_axi_cfg_aw_bits_cache,
  input  [2:0]                 s_axi_cfg_aw_bits_prot,
  input  [3:0]                 s_axi_cfg_aw_bits_qos,
  input  [3:0]                 s_axi_cfg_aw_bits_region,
  output                       s_axi_cfg_ar_ready,
  input                        s_axi_cfg_ar_valid,
  input  [S_AXID_BITS - 1:0]   s_axi_cfg_ar_bits_id,
  input  [S_AXADDR_BITS - 1:0] s_axi_cfg_ar_bits_addr,
  input  [7:0]                 s_axi_cfg_ar_bits_len,
  input  [2:0]                 s_axi_cfg_ar_bits_size,
  input  [1:0]                 s_axi_cfg_ar_bits_burst,
  input                        s_axi_cfg_ar_bits_lock,
  input  [3:0]                 s_axi_cfg_ar_bits_cache,
  input  [2:0]                 s_axi_cfg_ar_bits_prot,
  input  [3:0]                 s_axi_cfg_ar_bits_qos,
  input  [3:0]                 s_axi_cfg_ar_bits_region,
  output                       s_axi_cfg_w_ready,
  input                        s_axi_cfg_w_valid,
  input  [63:0]                s_axi_cfg_w_bits_data,
  input  [7:0]                 s_axi_cfg_w_bits_strb,
  input                        s_axi_cfg_w_bits_last,
  input                        s_axi_cfg_b_ready,
  output                       s_axi_cfg_b_valid,
  output [S_AXID_BITS - 1:0]   s_axi_cfg_b_bits_id,
  output [1:0]                 s_axi_cfg_b_bits_resp,
  input                        s_axi_cfg_r_ready,
  output                       s_axi_cfg_r_valid,
  output [S_AXID_BITS - 1:0]   s_axi_cfg_r_bits_id,
  output [63:0]                s_axi_cfg_r_bits_data,
  output [1:0]                 s_axi_cfg_r_bits_resp,
  output                       s_axi_cfg_r_bits_last,
  input                        m_axi_dma_aw_ready,
  output                       m_axi_dma_aw_valid,
  output [M_AXID_BITS - 1:0]   m_axi_dma_aw_bits_id,
  output [M_AXADDR_BITS - 1:0] m_axi_dma_aw_bits_addr,
  output [7:0]                 m_axi_dma_aw_bits_len,
  output [2:0]                 m_axi_dma_aw_bits_size,
  output [1:0]                 m_axi_dma_aw_bits_burst,
  output                       m_axi_dma_aw_bits_lock,
  output [3:0]                 m_axi_dma_aw_bits_cache,
  output [2:0]                 m_axi_dma_aw_bits_prot,
  output [3:0]                 m_axi_dma_aw_bits_qos,
  output [3:0]                 m_axi_dma_aw_bits_region,
  input                        m_axi_dma_ar_ready,
  output                       m_axi_dma_ar_valid,
  output [M_AXID_BITS - 1:0]   m_axi_dma_ar_bits_id,
  output [M_AXADDR_BITS - 1:0] m_axi_dma_ar_bits_addr,
  output [7:0]                 m_axi_dma_ar_bits_len,
  output [2:0]                 m_axi_dma_ar_bits_size,
  output [1:0]                 m_axi_dma_ar_bits_burst,
  output                       m_axi_dma_ar_bits_lock,
  output [3:0]                 m_axi_dma_ar_bits_cache,
  output [2:0]                 m_axi_dma_ar_bits_prot,
  output [3:0]                 m_axi_dma_ar_bits_qos,
  output [3:0]                 m_axi_dma_ar_bits_region,
  input                        m_axi_dma_w_ready,
  output                       m_axi_dma_w_valid,
  output [255:0]               m_axi_dma_w_bits_data,
  output [31:0]                m_axi_dma_w_bits_strb,
  output                       m_axi_dma_w_bits_last,
  output                       m_axi_dma_b_ready,
  input                        m_axi_dma_b_valid,
  input  [M_AXID_BITS - 1:0]   m_axi_dma_b_bits_id,
  input  [1:0]                 m_axi_dma_b_bits_resp,
  output                       m_axi_dma_r_ready,
  input                        m_axi_dma_r_valid,
  input  [M_AXID_BITS - 1:0]   m_axi_dma_r_bits_id,
  input  [255:0]               m_axi_dma_r_bits_data,
  input  [1:0]                 m_axi_dma_r_bits_resp,
  input                        m_axi_dma_r_bits_last,
  output [EXT_INTR_BITS - 1:0] ext_intr,
  input                        i_top_clk,
  output                       o_noc_clk,
  output [NR_CC-1:0]           o_cpu_clk,
  input                        i_top_rst,
  output                       o_noc_rst
);

  assign o_noc_clk = i_top_clk;
  assign o_cpu_clk = {NR_CC{i_top_clk}};
  assign o_noc_rst = i_top_rst;
  assign s_axi_cfg_aw_ready = 1'h0;
  assign s_axi_cfg_ar_ready = 1'h0;
  assign s_axi_cfg_w_ready = 1'h0;
  assign s_axi_cfg_b_valid = 1'h0;
  assign s_axi_cfg_b_bits_id = 0;
  assign s_axi_cfg_b_bits_resp = 2'h0;
  assign s_axi_cfg_r_valid = 1'h0;
  assign s_axi_cfg_r_bits_id = 0;
  assign s_axi_cfg_r_bits_data = 64'h0;
  assign s_axi_cfg_r_bits_resp = 2'h0;
  assign s_axi_cfg_r_bits_last = 1'h0;
  assign m_axi_dma_aw_valid = 1'h0;
  assign m_axi_dma_aw_bits_id = 0;
  assign m_axi_dma_aw_bits_addr = 0;
  assign m_axi_dma_aw_bits_len = 8'h0;
  assign m_axi_dma_aw_bits_size = 3'h0;
  assign m_axi_dma_aw_bits_burst = 2'h0;
  assign m_axi_dma_aw_bits_lock = 1'h0;
  assign m_axi_dma_aw_bits_cache = 4'h0;
  assign m_axi_dma_aw_bits_prot = 3'h0;
  assign m_axi_dma_aw_bits_qos = 4'h0;
  assign m_axi_dma_aw_bits_region = 4'h0;
  assign m_axi_dma_ar_valid = 1'h0;
  assign m_axi_dma_ar_bits_id = 0;
  assign m_axi_dma_ar_bits_addr = 0;
  assign m_axi_dma_ar_bits_len = 8'h0;
  assign m_axi_dma_ar_bits_size = 3'h0;
  assign m_axi_dma_ar_bits_burst = 2'h0;
  assign m_axi_dma_ar_bits_lock = 1'h0;
  assign m_axi_dma_ar_bits_cache = 4'h0;
  assign m_axi_dma_ar_bits_prot = 3'h0;
  assign m_axi_dma_ar_bits_qos = 4'h0;
  assign m_axi_dma_ar_bits_region = 4'h0;
  assign m_axi_dma_w_valid = 1'h0;
  assign m_axi_dma_w_bits_data = 256'h0;
  assign m_axi_dma_w_bits_strb = 32'h0;
  assign m_axi_dma_w_bits_last = 1'h0;
  assign m_axi_dma_b_ready = 1'h0;
  assign m_axi_dma_r_ready = 1'h0;
  assign ext_intr = 0;
endmodule
