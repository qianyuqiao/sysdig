m_buffer的映射
scap.c 

320行    len = RING_BUF_SIZE * 2;
366行    handle->m_devs[j].m_buffer = (char*)mmap(0, len, PROT_READ, MAP_SHARED, handle->m_devs[j].m_fd, 0);

ppm_ring_buffer_info的映射
387行    handle->m_devs[j].m_bufinfo = (struct ppm_ring_buffer_info*)mmap(0, sizeof(struct ppm_ring_buffer_info), 
                                        PROT_READ | PROT_WRITE, MAP_SHARED, handle->m_devs[j].m_fd, 0);
